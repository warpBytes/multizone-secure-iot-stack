/*
 * Copyright(C) 2018 Hex Five Security, Inc. - All rights reserved.
 */

#include <limits.h>

#include <platform.h>
#include <libhexfive.h>

int test(void)
{
    int i;

    for (i = 0; i < 1e6; i++) {

    }
}

int main(int argc, char *argv[]){
    test();

    printf("pico stack initialized\n");

    while (1)
    {
        int msg[4] = {0,0,0,0};

        if (ECALL_RECV(4, msg))
            ECALL_SEND(4, msg);
        ECALL_YIELD();
    }
    return 0;
}
