/**
 * Radio module
 *
 * This module provides all the required functions to manage the nRF51822
 * transceiver.
 **/

#pragma once
#include <Arduino.h>

extern uint8_t *rx_buffer; /* Rx buffer used by RF to store packets. */

uint8_t channel_to_freq(int channel);
void radio_disable(void);
void radio_set_sniff(int channel, uint32_t access_address);
void radio_send_custom(uint8_t *pBuffer, uint8_t channel, uint32_t access_address = 0x8E89BED6, uint32_t crc_init = 0x555555);
void radio_tx_to_rx();