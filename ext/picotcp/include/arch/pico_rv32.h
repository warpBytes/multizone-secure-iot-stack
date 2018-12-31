/*********************************************************************
   PicoTCP. Copyright (c) 2012-2017 Altran Intelligent Systems. Some rights reserved.
   See COPYING, LICENSE.GPLv2 and LICENSE.GPLv3 for usage.

 *********************************************************************/
#ifndef _INCLUDE_PICO_GCC
#define _INCLUDE_PICO_RV32

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "pico_constants.h"

#define dbg(...)
void *pico_zalloc(size_t size);
void pico_free(void *ptr);
pico_time PICO_TIME_MS(void);
pico_time PICO_TIME(void);
void PICO_IDLE(void);

#endif  /* PICO_RV32 */
