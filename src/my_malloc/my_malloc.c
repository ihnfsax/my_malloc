#include "my_malloc.h"
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* chunk size type 的大小 */
#if __GNUC__
#if __x86_64__ || __ppc64__
#define SIZE_SZ 8
#else
#define SIZE_SZ 4
#endif
#elif UINTPTR_MAX > UINT_MAX
#define SIZE_SZ 8
#else
#define SIZE_SZ 4
#endif

/* chunk size type */
#if (SIZE_SZ == 4)
#define INTERNAL_SIZE_T uint32_t
#else
#define INTERNAL_SIZE_T uint64_t
#endif

/* malloc chunk */
struct malloc_chunk {
    INTERNAL_SIZE_T mchunk_prev_size; /* 前面块若是空闲块，则表示其大小 */
    INTERNAL_SIZE_T mchunk_size;      /* 当前块总大小 */

    struct malloc_chunk* fd; /* 双向链表，仅当块空闲时使用 */
    struct malloc_chunk* bk;
};
typedef struct malloc_chunk* mchunkptr;

/* arena header */
struct malloc_state {
    /* 访问控制锁 */
    pthread_mutex_t mutex;
    /* 空闲链表 */
    mchunkptr head;
    mchunkptr tail;
    /* arena 链表 */
    struct malloc_state* next;
    /* arena free list, 受 free_list_lock 保护 */
    struct malloc_state* next_free;
    /* arena attach 的线程数量. 0 意味着该 arena 在空闲链表上.
       受 free_list_lock 保护 */
    INTERNAL_SIZE_T attached_threads;
};
typedef struct malloc_state* mstate;

/* heap */
typedef struct heap_info {
    INTERNAL_SIZE_T   total_size;
    INTERNAL_SIZE_T   free_chunk_size;
    mstate            ar_ptr;
    struct heap_info* prev;
} heap_info;

/* malloc 参数 */
struct malloc_config {
    /* 可调整的参数（用于自定义） */
    INTERNAL_SIZE_T arena_max; /* arena 数量上限 */
    INTERNAL_SIZE_T pagesize;  /* 页面大小 */
};

/* ---------------------------------------------------- */

/* heap 大小，必须是 2 的次幂 */
#define HEAP_MAX_SIZE (1024 * 1024)

/* 使用 mmap 的阈值 */
#define MMAP_THRESHOLD (128 * 1024)

/* 最小 chunk 大小（已对齐）*/
#define MINSIZE (sizeof(struct malloc_chunk))

/* chunk 地址(和大小)按照 2 * SIZE_SZ 对齐 */
#define MALLOC_ALIGNMENT (2 * SIZE_SZ)

/* chunk 对齐掩码 */
#define MALLOC_ALIGN_MASK (MALLOC_ALIGNMENT - 1)

/* 获取对齐后的地址 */
#define align_chunk(p) ((mchunkptr)(((unsigned long)(p) + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK))

/* 将用户请求大小转为合法的 chunk 大小 */
#define request2size(req) \
    (((req) + 2 * SIZE_SZ < MINSIZE) ? MINSIZE : ((req) + 2 * SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

/* chunk size 上的标志位 */
/* 当前块是否是空闲的 */
#define INUSE 0x1
/* 获取 INUSE 标志位 */
#define inuse_bit(p) ((p)->mchunk_size & INUSE)
/* 当该块是 mmap() 分配时置位 */
#define IS_MMAPPED 0x2
/* 获取 chunk 大小, 最小 3bit 要清掉 */
#define SIZE_BITS (INUSE | IS_MMAPPED | 0x4)
#define chunksize(p) ((p)->mchunk_size & ~(SIZE_BITS))
#define prevsize(p) ((p)->mchunk_prev_size & ~(SIZE_BITS))

/* 将 chunk 地址转为用户地址 */
#define chunk2mem(p) ((void*)((char*)(p) + 2 * SIZE_SZ))

/* 将用户地址转为 chunk 地址 */
#define mem2chunk(mem) ((mchunkptr)((char*)(mem)-2 * SIZE_SZ))

/* 根据 chunk 指针找到所属的 heap_info */
#define heap_for_ptr(p) ((heap_info*)((unsigned long)(p) & ~(HEAP_MAX_SIZE - 1)))

/* 获取 heap 结束的地址 */
#define heap_end(p) ((char*)(p) + (p)->total_size)

/* 获取更高地址块的地址 */
#define higher_chunk(p) ((mchunkptr)((char*)(p) + chunksize(p)))

/* 获取更低地址块的地址 */
#define lower_chunk(p) ((mchunkptr)((char*)(p)-prevsize(p)))

/* 两个地址是否在同一heap */
#define is_same_heap(p1, p2) (heap_for_ptr(p1) == heap_for_ptr(p2))

/* 获取 chunk 结束地址 */
// #define chunk_end(p) ((char*)(p) + p->mchunk_size)

/* ---------------------------------------------------- */

/* 全局 malloc 参数 */
static struct malloc_config mcconfig;

/* 是否被初始化了 */
static bool malloc_initialized = false;

/* thread arena pointer */
static __thread mstate thread_arena;

/* arena list lock */
static pthread_mutex_t list_lock = PTHREAD_MUTEX_INITIALIZER;
/* arena list */
static mstate arena_list;

/* arena free list, 此锁用来保护下面的变量以及 arena 头部里的 next_free
   和 attached_threads */
static pthread_mutex_t free_list_lock = PTHREAD_MUTEX_INITIALIZER;
/* 当前 arena 数量 */
static atomic_size_t narenas = 0;
/* arena free list 头部 */
static mstate free_arena_list;

/* next to use lock */
static pthread_mutex_t next_use_lock = PTHREAD_MUTEX_INITIALIZER;
/* arena next to use */
static mstate next_to_use;

/* 对齐后的新 heap 的地址，因为 mmap 不一定按照 HEAP_MAP_SIZE 对齐，所以要在调用 mmap 时，
   使用对齐后的 aligned_heap_area. 不用加锁，因为内核保证 mmap 的原子性，顶多就是多个 mmap
   传入了相同的地址，但是只有一个返回成功 */
static char* aligned_heap_area;

/* ---------------------------------------------------- */

/* 从空闲 arena 链表获取一个 arena */
static mstate arena_from_free_list();

/* 创建一个新的 arena */
static mstate new_arena();

/* 复用一个现有的 arena */
static mstate reused_arena();

/* 得到目的 arena */
static mstate arena_get();

static heap_info* new_heap();

/* 用 mmap 分配 chunk */
static void* chunk_by_mmap(size_t bytes);

/* internal malloc */
static void* int_malloc(mstate av, size_t bytes);

/* heap 是否已经全空了 */
static int is_heap_empty(heap_info* heap);

/* 必要时清理 heap */
static int heap_trim(heap_info* heap);

/* internal free */
static void int_free(mstate av, mchunkptr p);

/* list operations */
static void fisrt_chunk(mstate av, mchunkptr p);

static void delete_chunk(mstate av, mchunkptr p);

static void insert_after(mstate av, mchunkptr p, mchunkptr prev);

static void insert_before(mstate av, mchunkptr p, mchunkptr next);

static void check_list(mstate av);

/* ---------------------------------------------------- */

static void fisrt_chunk(mstate av, mchunkptr p) {
    assert(av->head == NULL);
    assert(av->tail == NULL);
    p->fd = p->bk = NULL;
    av->head = av->tail = p;
}

static void delete_chunk(mstate av, mchunkptr p) {
    assert(av->tail != NULL); /* arena 至少有一个空闲块 */
    if (p->bk)
        p->bk->fd = p->fd;
    else
        av->head = p->fd;
    if (p->fd)
        p->fd->bk = p->bk;
    else
        av->tail = p->bk;
    p->fd = p->bk = NULL;
}

static void insert_after(mstate av, mchunkptr p, mchunkptr prev) {
    assert(prev != NULL);
    p->fd = p->bk = NULL;
    if (prev->fd) {
        p->fd        = prev->fd;
        prev->fd->bk = p;
    }
    else
        av->tail = p;

    prev->fd = p;
    p->bk    = prev;
}

static void insert_before(mstate av, mchunkptr p, mchunkptr next) {
    assert(next != NULL);
    p->fd = p->bk = NULL;
    if (next->bk) {
        p->bk        = next->bk;
        next->bk->fd = p;
    }
    else
        av->head = p;

    next->bk = p;
    p->fd    = next;
}

static heap_info* new_heap() {
    char *        p1, *p2;
    unsigned long ul;
    heap_info*    h;

    p2 = (char*)MAP_FAILED;
    if (aligned_heap_area) {
        p2 = (char*)mmap(aligned_heap_area, HEAP_MAX_SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        aligned_heap_area = NULL;
        if (p2 != MAP_FAILED && ((unsigned long)p2 & (HEAP_MAX_SIZE - 1))) { /* 如果没有对齐 */
            munmap(p2, HEAP_MAX_SIZE);
            p2 = (char*)MAP_FAILED;
        }
    }
    if (p2 == MAP_FAILED) {
        p1 = (char*)mmap(0, HEAP_MAX_SIZE << 1, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p1 != MAP_FAILED) {
            p2 = (char*)(((unsigned long)p1 + (HEAP_MAX_SIZE - 1)) & ~(HEAP_MAX_SIZE - 1));  // 向高地址对齐
            ul = p2 - p1;
            if (ul) /* 取消低地址多余部分的映射 */
                munmap(p1, ul);
            else /* 直接对齐了 */
                aligned_heap_area = p2 + HEAP_MAX_SIZE;
            munmap(p2 + HEAP_MAX_SIZE, HEAP_MAX_SIZE - ul); /* 取消高地址多余部分的映射 */
        }
        else {
            /* 最后再试一次，看能否对齐 */
            p2 = (char*)mmap(aligned_heap_area, HEAP_MAX_SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (p2 == MAP_FAILED)
                return NULL;

            if ((unsigned long)p2 & (HEAP_MAX_SIZE - 1)) {
                munmap(p2, HEAP_MAX_SIZE);
                return NULL;
            }
        }
    }
    if (mprotect(p2, HEAP_MAX_SIZE, PROT_READ | PROT_WRITE) != 0) {
        munmap(p2, HEAP_MAX_SIZE);
        return NULL;
    }
    h             = (heap_info*)p2;
    h->total_size = HEAP_MAX_SIZE;
#ifdef HEAP_INFO
    printf("new heap is allocated at %p.\n", h);
#endif
    return h;
};

static mstate arena_from_free_list() {
    mstate av = free_arena_list;

    pthread_mutex_lock(&free_list_lock);
    if (av != NULL) {
        free_arena_list = free_arena_list->next_free;
        assert(av->attached_threads == 0);
        av->attached_threads = 1;
    }
    pthread_mutex_unlock(&free_list_lock);
    if (av != NULL) {
        thread_arena = av;
        pthread_mutex_lock(&av->mutex);
    }
    return av;
}

static mstate new_arena() {
    heap_info* h = new_heap();
    if (h == NULL)
        return NULL;
    h->prev   = NULL;
    mstate av = h->ar_ptr = (mstate)(h + 1);

    pthread_mutex_init(&av->mutex, NULL);
    fisrt_chunk(av, align_chunk(av + 1)); /* 初始化第一个空闲块 */
    av->attached_threads = 1;
    thread_arena         = av;
    h->free_chunk_size = av->head->mchunk_size = heap_end(h) - (char*)av->head;

    pthread_mutex_lock(&list_lock);
    if (arena_list == NULL) {
        arena_list = av;
        av->next   = av;
    }
    else {
        av->next         = arena_list->next;
        arena_list->next = av;
    }
    pthread_mutex_unlock(&list_lock);
    pthread_mutex_lock(&av->mutex);
    return av;
}

static mstate reused_arena() {
    mstate result = NULL;

    assert(arena_list != NULL);
    pthread_mutex_lock(&next_use_lock);
    if (next_to_use == NULL)
        next_to_use = arena_list;
    result = next_to_use;
    do {
        if (pthread_mutex_trylock(&result->mutex) == 0) {
            break;
        }
        result = result->next;
    } while (result != next_to_use);
    next_to_use = result->next;
    pthread_mutex_unlock(&next_use_lock);

    pthread_mutex_lock(&result->mutex); /* 可能阻塞 */

    if (result->attached_threads == 0) { /* 如果原来是空闲的，要把它从链表中取下 */
        pthread_mutex_lock(&free_list_lock);
        mstate* previous = &free_arena_list;
        for (mstate p = free_arena_list; p != NULL; p = p->next_free) {
            assert(p->attached_threads == 0);
            if (p == result) {
                *previous = p->next_free;
                break;
            }
            else {
                previous = &p->next_free;
            }
        }
        pthread_mutex_unlock(&free_list_lock);
    }
    thread_arena = result;
    ++result->attached_threads;
    return result;
}

static mstate arena_get() {
    mstate av = thread_arena;
    if (av != NULL) {
        pthread_mutex_lock(&av->mutex);
        return av;
    }
    else {
        if (free_arena_list != NULL) { /* 有空闲 arena */
            av = arena_from_free_list();
            if (av != NULL)
                return av;
        }
        if (narenas < mcconfig.arena_max) { /* arena 数量未达到上限 */
            return new_arena();
        }
        else {
            return reused_arena();
        }
    }
}

static void* chunk_by_mmap(size_t bytes) {
    INTERNAL_SIZE_T nb        = request2size(bytes);
    size_t          mmap_size = ((unsigned long)nb + mcconfig.pagesize) & ~mcconfig.pagesize;

    mchunkptr result = (mchunkptr)mmap(NULL, mmap_size, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (result == MAP_FAILED) {
        perror("mmap failed");
        exit(1);
    }

    result->mchunk_size = mmap_size;
    result->mchunk_size |= INUSE;
    result->mchunk_size |= IS_MMAPPED;
    return chunk2mem(result);
}

static void* int_malloc(mstate av, size_t bytes) {
    // check_list(av);

    INTERNAL_SIZE_T nb       = request2size(bytes); /* normalized chunk size */
    mchunkptr       iter     = av->head;            /* 迭代器 */
    mchunkptr       result   = NULL;                /* 目标 chunk */
    mchunkptr       old_tail = NULL;                /* 未分配前 av 的尾部块 */
    mchunkptr       higher   = NULL;                /* result 更高地址块 */

    assert(iter != NULL);
    for (; iter != av->tail; iter = iter->fd) {
        if (chunksize(iter) >= nb) {
            result = iter;
            break;
        }
    }

    if (result == NULL) {
        if (chunksize(av->tail) + MINSIZE < nb) { /* 没有一个 chunk 满足要求 */
            heap_info* h       = new_heap();
            h->prev            = heap_for_ptr(av->tail);
            h->ar_ptr          = av;
            h->free_chunk_size = heap_end(h) - (char*)align_chunk(h + 1);

            insert_after(av, align_chunk(h + 1), av->tail);
            av->tail->mchunk_size = heap_end(h) - (char*)av->tail;
        }
        result = av->tail;
    }

    old_tail = av->tail;
    delete_chunk(av, result); /* 从链表上取下 */

    INTERNAL_SIZE_T remainder_size = chunksize(result) - nb; /* 剩余 chunk 大小 */
    if (remainder_size >= MINSIZE) {                         /* 分割 */
        mchunkptr remainder         = (mchunkptr)((char*)result + nb);
        remainder->mchunk_size      = remainder_size;
        remainder->mchunk_prev_size = nb;

        if (av->tail == NULL) { /* 唯一一个块被取下了 */
            fisrt_chunk(av, remainder);
        }
        else {
            if (result == old_tail) /* 队尾分割出来的放在队尾 */
                insert_after(av, remainder, av->tail);
            else /* 其他的放在队尾前一个 */
                insert_before(av, remainder, av->tail);
        }
        result->mchunk_size -= remainder_size;
        assert(result->mchunk_size == nb);

        higher = higher_chunk(remainder);
        if (is_same_heap(remainder, higher)) {
            higher->mchunk_prev_size = chunksize(remainder);
        }
    }
    else { /* 无法分割 */
        assert(result != old_tail);
    }

    assert(inuse_bit(result) == 0);

    result->mchunk_size |= INUSE;

    heap_for_ptr(result)->free_chunk_size -= chunksize(result);

    memset(chunk2mem(result), 0, chunksize(result) - 2 * SIZE_SZ);

    return chunk2mem(result);
};

static int is_heap_empty(heap_info* h) {
    char* chunk_start = NULL;

    if (is_same_heap(h, h->ar_ptr)) {
        assert(h->prev == NULL);
        chunk_start = (char*)align_chunk(h->ar_ptr + 1);
    }
    else {
        assert(h->prev != NULL);
        chunk_start = (char*)align_chunk(h + 1);
    }

    return ((long int)h->free_chunk_size == heap_end(h) - chunk_start);
}

static int heap_trim(heap_info* heap) {
    heap_info* prev_heap = heap->prev;   /* 上一个 heap */
    mstate     ar_ptr    = heap->ar_ptr; /* heap 所属 arena */
    mchunkptr  iter      = ar_ptr->head; /* 迭代器*/
    mchunkptr  highest   = NULL;         /* 最高地址空闲块 */

    if (!is_heap_empty(heap) || prev_heap == NULL || !is_same_heap(heap, ar_ptr->tail)) {
        return 1;
    }

    assert(align_chunk(heap + 1) == ar_ptr->tail);

    /* 寻找 prev_heap 中地址最高的块 */
    for (; iter != NULL; iter = iter->fd) {
        assert(inuse_bit(iter) == 0);
        if (is_same_heap(prev_heap, iter)) {
            if (iter > highest) {
                highest = iter;
            }
        }
    }

    assert(!is_same_heap(highest, heap));
    assert(highest != ar_ptr->tail);

    if (highest == NULL) /* 概率极小：prev_heap 没有空闲块 */
        return 1;

    if ((char*)higher_chunk(highest) == heap_end(prev_heap)) {
        delete_chunk(ar_ptr, ar_ptr->tail); /* 删除原来的 tail */

        /* 将 highest chunk 挪到链表 tail 处 */
        if (highest != ar_ptr->tail) {
            delete_chunk(ar_ptr, highest);
            insert_after(ar_ptr, highest, ar_ptr->tail);
        }

#ifdef HEAP_INFO
        printf("heap at %p is destroyed.\n", heap);
#endif
        munmap(heap, heap->total_size);

        if (is_heap_empty(prev_heap)) {
            heap_trim(prev_heap);
        }
        return 0;
    }

    return 1;
}

static void int_free(mstate av, mchunkptr p) {
    // check_list(av);

    assert(p->mchunk_size >= MINSIZE);
    assert(inuse_bit(p) != 0);
    assert((p->mchunk_size & IS_MMAPPED) == 0);

    bool            if_insert = true;
    bool            is_tail   = false;
    INTERNAL_SIZE_T free_size = chunksize(p);
    heap_info*      h         = heap_for_ptr(p);

    assert(h->ar_ptr == av);

    p->mchunk_size &= ~INUSE;

    mchunkptr higher = higher_chunk(p);
    is_tail          = higher == av->tail;
    assert(!is_tail || (is_tail && inuse_bit(higher) == 0));
    if (is_same_heap(p, higher)) {
        if (inuse_bit(higher) == 0) { /* 合并 */
            p->mchunk_size += chunksize(higher);
            delete_chunk(av, higher);
        }
    }

    mchunkptr lower = lower_chunk(p);
    if (lower != p && is_same_heap(p, lower)) {
        if (inuse_bit(lower) == 0) { /* 合并 */
            p->mchunk_size += chunksize(lower);
            lower->mchunk_size = p->mchunk_size;
            p                  = lower;
            if (is_tail)
                delete_chunk(av, lower);
            else
                if_insert = false;
        }
    }

    mchunkptr higher_2 = higher_chunk(p);
    if (is_same_heap(p, higher_2)) {
        higher_2->mchunk_prev_size = chunksize(p);
    }

    if (if_insert) {
        if (is_tail && av->tail)
            insert_after(av, p, av->tail);
        else if (av->head)
            insert_before(av, p, av->head);
        else {
            assert(av->head == NULL && av->tail == NULL);
            fisrt_chunk(av, p);
        }
    }

    h->free_chunk_size += free_size;

#ifndef NO_HEAP_TRIM
    heap_trim(h);
#endif
}

void* my_malloc(size_t bytes) {
    if (!malloc_initialized) {
        mcconfig.arena_max = sysconf(_SC_NPROCESSORS_ONLN);
        mcconfig.pagesize  = sysconf(_SC_PAGE_SIZE);
        malloc_initialized = true;
    }

    if (bytes >= MMAP_THRESHOLD) {
        return chunk_by_mmap(bytes);
    }

    mstate ar_ptr = arena_get();

    if (ar_ptr == NULL) {
        return NULL;
    }

    void* mem = int_malloc(ar_ptr, bytes);

    // printf("malloc chunk size %ld, addr %p\n", chunksize(mem2chunk(mem)), mem2chunk(mem));
    // mchunkptr iter = ar_ptr->head;
    // for (; iter != NULL; iter = iter->fd) {
    //     printf("[C%p S%ld]", iter, iter->mchunk_size);
    //     if (iter->fd != NULL) {
    //         printf(" --> ");
    //     }
    // }
    // printf("\n");
    // iter = ar_ptr->tail;
    // for (; iter != NULL; iter = iter->bk) {
    //     printf("[C%p S%ld]", iter, iter->mchunk_size);
    //     if (iter->bk != NULL) {
    //         printf(" <-- ");
    //     }
    // }
    // printf("\n\n");

    pthread_mutex_unlock(&ar_ptr->mutex);

    return mem;
}

void my_free(void* mem) {
    if (mem == NULL)
        return;

    mchunkptr p = mem2chunk(mem);

    // printf("free chunk size %ld, addr %p\n", chunksize(p), p);

    if (p->mchunk_size & IS_MMAPPED) {
        munmap(p, chunksize(p));
        return;
    }

    mstate ar_ptr = heap_for_ptr(p)->ar_ptr;

    assert(ar_ptr != NULL);

    pthread_mutex_lock(&ar_ptr->mutex);

    int_free(ar_ptr, p);

    // mchunkptr iter = ar_ptr->head;
    // for (; iter != NULL; iter = iter->fd) {
    //     printf("[C%p S%ld]", iter, iter->mchunk_size);
    //     if (iter->fd != NULL) {
    //         printf(" --> ");
    //     }
    // }
    // printf("\n");
    // iter = ar_ptr->tail;
    // for (; iter != NULL; iter = iter->bk) {
    //     printf("[C%p S%ld]", iter, iter->mchunk_size);
    //     if (iter->bk != NULL) {
    //         printf(" <-- ");
    //     }
    // }
    // printf("\n\n");

    pthread_mutex_unlock(&ar_ptr->mutex);

    return;
}

void exit_malloc() {
    mstate a     = thread_arena;
    thread_arena = NULL;

    if (a != NULL) {
        pthread_mutex_lock(&free_list_lock);
        assert(a->attached_threads > 0);
        if (--a->attached_threads == 0) {
            a->next_free    = free_arena_list;
            free_arena_list = a;
        }
        pthread_mutex_unlock(&free_list_lock);
    }
}

/* FOR DEBUG */
static void check_list(mstate av) {
    mchunkptr iter = av->head, highest = NULL;
    while (iter) {
        mchunkptr higher = higher_chunk(iter);
        mchunkptr lower  = lower_chunk(iter);
        if (is_same_heap(iter, higher))
            assert(prevsize(higher) == chunksize(iter));
        if (iter != lower && is_same_heap(iter, lower))
            assert(prevsize(iter) == chunksize(lower));
        if (iter > highest)
            highest = iter;
        iter = iter->fd;
    }
    assert(highest == av->tail);
}

#ifdef __cplusplus
}
#endif /* __cplusplus */