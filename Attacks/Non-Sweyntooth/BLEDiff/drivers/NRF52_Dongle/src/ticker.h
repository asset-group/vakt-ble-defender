#ifndef _TIMER_H_
#define _TIMER_H_
#include <nrf_timer.h>

typedef void (*funcPtr_t)();

class Ticker
{
public:
    Ticker(int timer = 1);
    void attachInterrupt(funcPtr_t callback, int microsec);
    void detachInterrupt();

private:
    NRF_TIMER_Type *nrf_timer;
    nrf_timer_cc_channel_t cc_channel;
};

extern NRF_TIMER_Type *nrf_timers[5];
extern Ticker *Timers[5];

#endif // _TIMER_H_
