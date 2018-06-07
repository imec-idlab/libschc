#ifndef COMPRESSOR_CONFIG_H_
#define COMPRESSOR_CONFIG_H_

#include "scheduler.h"
#include "timer.h"

#define SCHC_CONF_RX_CONNS		2

void schc_init_task(void (*timer_task)()) {
    sched_register_task(timer_task);
}

void schc_post_task(void (*timer_task)(), uint16_t time_ms, uint32_t device_id) {
	timer_post_task_delay(timer_task, time_ms);
}


#endif
