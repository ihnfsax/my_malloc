#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

void* fn(void* arg) {
    int* a = (int*)malloc(sizeof(int));
    free(a);
    return NULL;
}

int main() {
    pthread_t pId;
    int       ret;
    ret = pthread_create(&pId, NULL, fn, NULL);

    if (ret != 0) {
        printf("create pthread error!\n");
        exit(1);
    }

    fn(NULL);

    pthread_join(pId, NULL);
    return 0;
}
