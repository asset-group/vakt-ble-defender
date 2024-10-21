/**
 * Radio module
 *
 * This module provides all the required functions to manage the nRF51822
 * transceiver.
 **/

#pragma once
#include <Arduino.h>

#define FEM_CS NRF_GPIO_PIN_MAP(0, 21)
#define FEM_PDN NRF_GPIO_PIN_MAP(0, 23)
#define FEM_MODE NRF_GPIO_PIN_MAP(0, 17)
#define FEM_RXEN NRF_GPIO_PIN_MAP(0, 19)
#define FEM_TXEN NRF_GPIO_PIN_MAP(0, 22)
#define FEM_ANTSEL NRF_GPIO_PIN_MAP(0, 20)

extern uint8_t *rx_buffer; /* Rx buffer used by RF to store packets. */

uint8_t channel_to_freq(int channel);
void radio_disable(void);
void radio_set_sniff(int channel, uint32_t access_address);
void radio_send_custom(uint8_t *pBuffer, uint8_t channel, uint32_t access_address = 0x8E89BED6, uint32_t crc_init = 0x555555);
void radio_tx_to_rx(uint8_t en_bcc = 0);
void radio_set_sniff_peripheral(int channel, uint32_t access_address, uint32_t crc_init);
