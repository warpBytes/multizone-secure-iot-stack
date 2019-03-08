/**
 * Copyright(C) 2018 Hex Five Security, Inc. - All Rights Reserved
 *
 * @author 	Sandro Pinto <sandro2pinto@gmail.com>
 * @author 	José Martins <josemartins90@gmail.com>
 * 
 */

/* TODO Add any manufacture supplied header files can be included
here. */
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "platform.h"
#include "plic_driver.h"

#include <libhexfive.h>
#include <mzmsg.h>
#include <cli.h>

int main(void)
{
    open("UART", 0, 0);
    cliTask(NULL);
}
