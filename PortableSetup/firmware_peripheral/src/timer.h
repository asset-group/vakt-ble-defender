#pragma once
#include "helpers.h"

void timer3_start(funcPtr_t callback, uint32_t microseconds);
void timer3_update(uint32_t microseconds);
void timer3_stop();
void timer4_start(funcPtr_t callback, uint32_t microseconds);
void timer4_update(uint32_t microseconds);
void timer4_stop();
