#include <Arduino.h>
#include <nrf_timer.h>
#include "helpers.h"
#include "timer.h"

// Timer variables
static funcPtr_t timer_callback = nullptr; // Callback function pointer

/**
 * nRF51822 Timer4 handler.
 *
 * General purpose timer
 **/

extern "C" void TIMER4_IRQHandler(void)
{
	NRF_TIMER4->EVENTS_COMPARE[0] = 0;

	if (timer_callback)
		timer_callback();
}

void start_timer(funcPtr_t callback, uint32_t microseconds)
{
	timer_callback = callback;
	NVIC_ClearPendingIRQ(TIMER4_IRQn);
	NRF_TIMER4->BITMODE = TIMER_BITMODE_BITMODE_32Bit;
	NRF_TIMER4->CC[0] = microseconds;
	NRF_TIMER4->INTENSET = TIMER_INTENSET_COMPARE0_Msk;
	NRF_TIMER4->SHORTS = TIMER_SHORTS_COMPARE0_CLEAR_Msk;
	NRF_TIMER4->PRESCALER = NRF_TIMER_FREQ_1MHz;
	NVIC_EnableIRQ(TIMER4_IRQn);
	NVIC_SetPriority(TIMER4_IRQn, IRQ_PRIORITY_LOW); // Highest interrupt priority
	NRF_TIMER4->TASKS_CLEAR = 1;
	NRF_TIMER4->TASKS_START = 1;
}

void update_timer(uint32_t microseconds)
{
	NRF_TIMER4->CC[0] = microseconds;
}

void stop_timer()
{
	NVIC_DisableIRQ(TIMER4_IRQn);
	NRF_TIMER4->EVENTS_COMPARE[0] = 0;
	NRF_TIMER4->TASKS_CLEAR = 1;
	NRF_TIMER4->TASKS_STOP = 1;
}