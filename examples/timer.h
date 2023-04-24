#ifndef TIME_H
#define TIME_H
#include <stdlib.h>

typedef enum
{
TIMER_SINGLE_SHOT = 0,
TIMER_PERIODIC
} t_timer;

struct timer_node
{
    int                 fd;
    void (*callback)(struct timer_node * timer_id, void * user_data);
    void *              user_data;
    unsigned int        interval;
    t_timer             type;
    struct timer_node * next;
};

typedef void (*time_handler)(struct timer_node * timer_id, void * user_data);

int initialize_timer_thread();
struct timer_node * start_timer(unsigned int interval, time_handler handler, t_timer type, void * user_data);
void stop_timer(struct timer_node * timer_id);
void finalize_timer_thread();

#endif
