#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include "mini_crypto.h"

#define BUF 2048
#define NUM_THREADS 4

struct thread_data {
    int thread_id;
    int sock;
    struct sockaddr_in addr;
    unsigned char key[32];
    u64 seq;
    u64 replay_bitmap;
};

void *handle_traffic(void *threadarg)
{
    struct thread_data *my_data = (struct thread_data *) threadarg;
    int sock = my_data->sock;
    unsigned char buf[BUF], out[BUF];
    unsigned long long seq;

    while (1) {
        int n = recv(sock, buf, BUF, 0);
        if (n <= 0) continue;

        seq = *(u64 *)buf;  // 假设序列号位于 payload 开头

        // 防重放窗口
        if (my_data->replay_bitmap & (1ULL << seq)) {
            continue;  // 跳过已重放包
        }

        mini_decrypt(out, buf + 8, n - 8, my_data->key, seq);

        // 更新 stats 和 replay 窗口
        my_data->replay_bitmap |= (1ULL << seq);

        write(1, out, n - 24);
    }
    pthread_exit(NULL);
}

int main()
{
    int sock;
    struct sockaddr_in addr;
    pthread_t threads[NUM_THREADS];
    struct thread_data thread_data_array[NUM_THREADS];
    FILE *f = fopen("/etc/mini/key.bin", "rb");

    if (!f) {
        perror("Key file not found!");
        return 1;
    }
    fread(thread_data_array[0].key, 1, 32, f);
    fclose(f);

    mini_crypto_init();
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(50000);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(sock, (struct sockaddr *)&addr, sizeof(addr));

    for (int i = 0; i < NUM_THREADS; i++) {
        thread_data_array[i].sock = sock;
        thread_data_array[i].addr = addr;
        pthread_create(&threads[i], NULL, handle_traffic, (void *)&thread_data_array[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}
