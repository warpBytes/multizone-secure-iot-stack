/* Copyright(C) 2018 Hex Five Security, Inc. - All Rights Reserved */

#include <mzmsg.h>
#include <string.h>
#include <libhexfive.h>

void mzmsg_init(mzmsg_t *mzmsg, int zone){
    mzmsg->zone = zone;
}

int mzmsg_read(mzmsg_t *mzmsg, char *buf, size_t len){
    char data[16];
    int i = 0;

    while (i < len) {
        if (ECALL_RECV(mzmsg->zone, data)) {
            buf[i] = data[0];
            i += 1;
        }
        ECALL_YIELD();
    }

    return i;
}

int mzmsg_write(mzmsg_t *mzmsg, char *buf, size_t len){
    int i = 0;
    char data[16];

    while (i < len) {
        int transfer = len - i;
        if (transfer > 16)
            transfer = 16;

        memset(data, 0, 16);
        memcpy(data, buf, transfer);

        if (ECALL_SEND(mzmsg->zone, data)) {
            i += transfer;
            buf += transfer;
        }
        ECALL_YIELD();
    }

    if (len % 16 == 0) {
        memset(data, 0, 16);
        while (!ECALL_SEND(mzmsg->zone, data)) {
            ECALL_YIELD();
        }
    }

    return i;
}
