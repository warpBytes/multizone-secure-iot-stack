/* Copyright(C) 2018 Hex Five Security, Inc. - All Rights Reserved */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <inttypes.h>
#include <math.h> // round()

#include <platform.h>
#include <libhexfive.h>

int main (void) {
	while(1){
        ECALL_YIELD();
	}
    return 0;
} // main()
