# My malloc

个人学习 ptmalloc 后的小实验，仿写了 my malloc (`src/my_malloc`)。

## 构建

```bash
cd src/test
make
```

## 测试

`bin` 目录下

- `my_malloc_benchtest/bench-malloc-thread`: 测试两秒内 my malloc 完成多少迭代，可测多线程。
- `glibc_benchtest/bench-malloc-thread`: 测试两秒内 ptmalloc 完成多少迭代，可测多线程，与 my malloc 进行对比。
- `simple_test`: 测试 my malloc 中 heap 的创建与销毁（取消 printf 注释）。

## 不足

- 不知道如何设置线程退出时自动 detach arena，只能手动调用 `exit_malloc()`；
- `heap_trim()` 释放 heap 的时机为：1. 该 heap 上只有 top chunk。2. 上一个 heap 有块可以当作新的 top chunk。测试发现，`heap_trim()` 非常影响性能，应该有更好的方式。
- 没有实现 bins 机制，只有一条双向链表，分配速度不及 ptmalloc。
- 不知道什么时候以及如何释放 arena（即第一个 heap）。