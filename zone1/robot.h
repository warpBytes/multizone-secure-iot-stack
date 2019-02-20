#ifndef ROBOT_H
#define ROBOT_H

#include <platform.h> 
#include <FreeRTOS.h>
#include <task.h>     /* RTOS task related API prototypes. */
#include <queue.h>   /* RTOS queue related API prototypes. */

extern QueueHandle_t robot_queue;
extern TaskHandle_t cli_task;
void robotTask( void *pvParameters );

#endif
