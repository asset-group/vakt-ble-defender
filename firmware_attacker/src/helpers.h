#pragma once
#include <Arduino.h>

#define IRQ_PRIORITY_HIGHEST 0
#define IRQ_PRIORITY_HIGH 1
#define IRQ_PRIORITY_MEDIUM 2
#define IRQ_PRIORITY_LOW 3

#define lowNibble(w) ((uint8_t)((w)&0x0F))
#define highNibble(w) ((uint8_t)(((w) >> 4) & 0x0F))

#define gpioWrite(pin, bitvalue) (bitvalue ? NRF_GPIO->OUTSET = (1 << pin) : NRF_GPIO->OUTCLR = (1 << pin))
#define gpioRead(pin) bitRead(NRF_GPIO->IN, pin)

typedef void (*funcPtr_t)();

uint32_t btle_reverse_crc(uint32_t crc, uint8_t *data, int len);
uint8_t swap_bits(uint8_t b);
void dewhiten(uint8_t *data, int len, int channel);
int is_valid_aa(uint32_t aa);
void chm_to_array(uint8_t *chm, uint8_t *chmArray);
void array_to_chm(uint8_t *chmArray, uint8_t *chm);
void bytes_to_hex(uint8_t *dst_array, uint8_t *src_array, uint16_t src_len);