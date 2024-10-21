#include <Arduino.h>
#include "nrf_timer.h"
#include "ticker.h"

static void defaultFunc(){};
static funcPtr_t Timer_callbackPtr;

Ticker::Ticker(int timer)
{
    nrf_timer = nrf_timers[timer];
    cc_channel = nrf_timer_cc_channel_t(0); // Using channel 0

    Timer_callbackPtr = defaultFunc;

    // Timer mode with 32bit width
    nrf_timer_bit_width_set(nrf_timer, NRF_TIMER_BIT_WIDTH_32);
    nrf_timer_mode_set(nrf_timer, NRF_TIMER_MODE_TIMER);
    nrf_timer_frequency_set(nrf_timer, NRF_TIMER_FREQ_1MHz);
}

void Ticker::attachInterrupt(funcPtr_t callback, int microsec)
{
    // This function will be called when time out interrupt will occur
    Timer_callbackPtr = callback;

    // Start if not already running (and reset?)
    nrf_timer_task_trigger(nrf_timer, NRF_TIMER_TASK_START);
    nrf_timer_task_trigger(nrf_timer, NRF_TIMER_TASK_CLEAR);
    nrf_timer_shorts_enable(nrf_timer, TIMER_SHORTS_COMPARE0_CLEAR_Pos << cc_channel);
    // Clear and enable compare interrupt
    nrf_timer_int_mask_t chanel_mask = nrf_timer_compare_int_get(cc_channel);
    nrf_timer_int_enable(nrf_timer, chanel_mask);

    if (nrf_timer == nrf_timers[0])
    {
        NVIC_EnableIRQ(TIMER0_IRQn);
        NVIC_SetPriority(TIMER0_IRQn, 0); // Highest interrupt priority
    }
    else if (nrf_timer == nrf_timers[1])
    {
        NVIC_EnableIRQ(TIMER1_IRQn);
        NVIC_SetPriority(TIMER1_IRQn, 0); // Highest interrupt priority
    }
    else if (nrf_timer == nrf_timers[2])
    {
        NVIC_EnableIRQ(TIMER2_IRQn);
    }
    else if (nrf_timer == nrf_timers[3])
    {
        NVIC_EnableIRQ(TIMER3_IRQn);
        NVIC_SetPriority(TIMER3_IRQn, 0); // Highest interrupt priority
    }
    else if (nrf_timer == nrf_timers[4])
    {
        NVIC_EnableIRQ(TIMER4_IRQn);
    }

    nrf_timer_cc_write(nrf_timer, cc_channel, microsec);
}

// Should be called in the Timer_callbackPtr() function
void Ticker::detachInterrupt()
{
    // Stop timer
    nrf_timer_task_trigger(nrf_timer, NRF_TIMER_TASK_STOP);

    // Disable timer compare interrupt
    nrf_timer_int_mask_t chanel_mask = nrf_timer_compare_int_get(cc_channel);
    nrf_timer_int_disable(nrf_timer, chanel_mask);

    // Clear event - TODO?
    nrf_timer_event_t event = nrf_timer_compare_event_get(chanel_mask);
    nrf_timer_event_clear(nrf_timer, event);
}

// Timer 0 is used by the soft device but Timer 1, 2, 3 and 4 are available
extern "C" void TIMER0_IRQHandler(void)
{
    NRF_TIMER0->EVENTS_COMPARE[0] = 0;
    Timer_callbackPtr();
}

extern "C" void TIMER1_IRQHandler(void)
{
    NRF_TIMER1->EVENTS_COMPARE[0] = 0;
    Timer_callbackPtr();
}

extern "C" void TIMER3_IRQHandler(void)
{
    NRF_TIMER3->EVENTS_COMPARE[0] = 0;
    Timer_callbackPtr();
}

extern "C" void TIMER4_IRQHandler(void)
{
    NRF_TIMER4->EVENTS_COMPARE[0] = 0;
    Timer_callbackPtr();
}

NRF_TIMER_Type *nrf_timers[] = {NRF_TIMER0, NRF_TIMER1, NRF_TIMER2,
                                NRF_TIMER3, NRF_TIMER4};

Ticker *Timers[5] = {0};
