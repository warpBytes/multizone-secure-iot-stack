/* Copyright(C) 2018 Hex Five Security, Inc. - All Rights Reserved */

#include <platform.h>
#include <libhexfive.h>

int main(void)
{
    while (1) {
        ECALL_YIELD();
    }
}
