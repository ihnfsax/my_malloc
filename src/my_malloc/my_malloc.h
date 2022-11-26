/**
 * \file            my_malloc.h
 * \brief           my_malloc include file
 */

#ifndef MYMALLOC_HDR_H
#define MYMALLOC_HDR_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* api privided to user */
void* my_malloc(size_t bytes);

void my_free(void* mem);

void exit_malloc();

// void print_heap_list();`

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MYMALLOC_HDR_H */