// main.c

#include "my_malloc.h"
#include <stdlib.h>

int main() {
    void* a[3000];
    for (int i = 0; i < 3000; ++i)
        a[i] = my_malloc(1000 + rand() % 1000);

    for (int i = 0; i < 3000; ++i)
        my_free(a[i]);

    exit_malloc();
    return 0;
}