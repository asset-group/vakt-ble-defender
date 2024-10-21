#include <Arduino.h>
#include "radio.h"
#include "helpers.h"

/**
 * channel_to_freq(int channel)
 *
 * Convert a BLE channel number into the corresponding frequency offset
 * for the nRF51822.
 **/

uint8_t channel_to_freq(int channel)
{
  if (channel == 37)
    return 2;
  else if (channel == 38)
    return 26;
  else if (channel == 39)
    return 80;
  else if (channel < 11)
    return 2 * (channel + 2);
  else
    return 2 * (channel + 3);
}

/**
 * radio_disable()
 *
 * Disable the radio.
 **/

void radio_disable(void)
{
  if (NRF_RADIO->STATE > 0)
  {
    NVIC_DisableIRQ(RADIO_IRQn);

    NRF_RADIO->EVENTS_DISABLED = 0;
    NRF_RADIO->TASKS_DISABLE = 1;
    while (NRF_RADIO->EVENTS_DISABLED == 0)
      ;
  }
}

/**
 * radio_set_sniff(int channel)
 *
 * Configure the nRF51822 to sniff on a specific channel.
 **/

void radio_set_sniff(int channel, uint32_t access_address)
{
  // Disable radio
  radio_disable();

  // Enable the High Frequency clock on the processor. This is a pre-requisite for
  // the RADIO module. Without this clock, no communication is possible.
  NRF_CLOCK->EVENTS_HFCLKSTARTED = 0;
  NRF_CLOCK->TASKS_HFCLKSTART = 1;
  while (NRF_CLOCK->EVENTS_HFCLKSTARTED == 0)
    ;

  // power should be one of: -30, -20, -16, -12, -8, -4, 0, 4
  NRF_RADIO->TXPOWER = RADIO_TXPOWER_TXPOWER_Pos4dBm;
  NRF_RADIO->TXADDRESS = 0;
  // Enable logical address 0 (rule to filter address received)
  bitSet(NRF_RADIO->RXADDRESSES, RADIO_RXADDRESSES_ADDR0_Pos);

  /* Set BLE data rate. */
  NRF_RADIO->MODE = (RADIO_MODE_MODE_Ble_1Mbit << RADIO_MODE_MODE_Pos);

  /* Listen on channel . */
  NRF_RADIO->FREQUENCY = channel_to_freq(channel);
  NRF_RADIO->DATAWHITEIV = channel;
  NRF_RADIO->PREFIX0 = (access_address >> 24) & RADIO_PREFIX0_AP0_Msk;
  NRF_RADIO->BASE0 = access_address << 8;

  /* PCNF-> Packet Configuration. Now we need to configure the sizes S0, S1 and length field to match the datapacket format of the advertisement packets. */
  NRF_RADIO->PCNF0 = ((((1UL) << RADIO_PCNF0_S0LEN_Pos) & RADIO_PCNF0_S0LEN_Msk)   // length of S0 field in bytes 0-1.
                      | (((0UL) << RADIO_PCNF0_S1LEN_Pos) & RADIO_PCNF0_S1LEN_Msk) // length of S1 field in bits 0-8.
                      | (((8UL) << RADIO_PCNF0_LFLEN_Pos) & RADIO_PCNF0_LFLEN_Msk) // length of length field in bits 0-8.
  );

  /* Packet configuration */
  NRF_RADIO->PCNF1 = ((((251UL) << RADIO_PCNF1_MAXLEN_Pos) & RADIO_PCNF1_MAXLEN_Msk)                           // maximum length of payload in bytes [0-255]
                      | (((0UL) << RADIO_PCNF1_STATLEN_Pos) & RADIO_PCNF1_STATLEN_Msk)                         // expand the payload with N bytes in addition to LENGTH [0-255]
                      | (((3UL) << RADIO_PCNF1_BALEN_Pos) & RADIO_PCNF1_BALEN_Msk)                             // base address length in number of bytes.
                      | (((RADIO_PCNF1_ENDIAN_Little) << RADIO_PCNF1_ENDIAN_Pos) & RADIO_PCNF1_ENDIAN_Msk)     // endianess of the S0, LENGTH, S1 and PAYLOAD fields.
                      | (((RADIO_PCNF1_WHITEEN_Enabled) << RADIO_PCNF1_WHITEEN_Pos) & RADIO_PCNF1_WHITEEN_Msk) // enable packet whitening
  );
  NRF_RADIO->MODECNF0 |= RADIO_MODECNF0_RU_Fast; // Enable fast mode for radio ramp up

  // Enable CRC
  NRF_RADIO->CRCPOLY = ((0x00065B << RADIO_CRCPOLY_CRCPOLY_Pos) & RADIO_CRCPOLY_CRCPOLY_Msk); // CRC polynomial function
  NRF_RADIO->CRCCNF = (((RADIO_CRCCNF_SKIPADDR_Skip) << RADIO_CRCCNF_SKIPADDR_Pos) & RADIO_CRCCNF_SKIPADDR_Msk) | (((RADIO_CRCCNF_LEN_Three) << RADIO_CRCCNF_LEN_Pos) & RADIO_CRCCNF_LEN_Msk);
  NRF_RADIO->CRCINIT = ((0x555555 << RADIO_CRCINIT_CRCINIT_Pos) & RADIO_CRCINIT_CRCINIT_Msk); // Initial value of CRC

  // Preset Access Address and set receive buffer
  uint8_t *aa = (uint8_t *)&access_address;
  rx_buffer -= 4;
  rx_buffer[0] = aa[0];
  rx_buffer[1] = aa[1];
  rx_buffer[2] = aa[2];
  rx_buffer[3] = aa[3];
  rx_buffer += 4;

  NRF_RADIO->PACKETPTR = (uint32_t)(rx_buffer); // + 4 bytes for padding the access address
  // Configure interrupts
  NRF_RADIO->INTENSET = RADIO_INTENSET_END_Msk;

  // Enable NVIC Interrupt for Radio
  NVIC_SetPriority(RADIO_IRQn, IRQ_PRIORITY_LOW);
  NVIC_ClearPendingIRQ(RADIO_IRQn);
  NVIC_EnableIRQ(RADIO_IRQn);

  // Enable receiver hardware
  NRF_RADIO->EVENTS_READY = 0;
  NRF_RADIO->TASKS_RXEN = 1;
  while (NRF_RADIO->EVENTS_READY == 0)
    ;
  NRF_RADIO->EVENTS_END = 0;
  NRF_RADIO->TASKS_START = 1;
}

/**
 * Send raw data asynchronously.
 **/

void radio_send_custom(uint8_t *pBuffer, uint8_t channel, uint32_t access_address, uint32_t crc_init)
{

  /* No shorts on disable. */
  NRF_RADIO->SHORTS = 0x0;
  /* Switch radio to TX. */
  radio_disable();

  /* Switch packet buffer to tx_buffer. */
  NRF_RADIO->PACKETPTR = (uint32_t)pBuffer;
  // NRF_RADIO->INTENSET = 1 << RADIO_INTENSET_END_Pos;
  NVIC_ClearPendingIRQ(RADIO_IRQn);
  NVIC_EnableIRQ(RADIO_IRQn);

  /* Transmit with max power. */
  NRF_RADIO->TXPOWER = (RADIO_TXPOWER_TXPOWER_Pos4dBm << RADIO_TXPOWER_TXPOWER_Pos);
  NRF_RADIO->TIFS = 0;
  NRF_RADIO->FREQUENCY = channel_to_freq(channel);
  NRF_RADIO->DATAWHITEIV = channel;
  NRF_RADIO->SHORTS = RADIO_SHORTS_READY_START_Msk | RADIO_SHORTS_END_DISABLE_Msk;
  // NRF_RADIO->INTENSET = RADIO_INTENSET_END_Msk;
  // Update access address
  uint8_t *aa = (uint8_t *)&access_address;
  rx_buffer -= 4;
  rx_buffer[0] = aa[0];
  rx_buffer[1] = aa[1];
  rx_buffer[2] = aa[2];
  rx_buffer[3] = aa[3];
  rx_buffer += 4;

  NRF_RADIO->PREFIX0 = (access_address >> 24) & RADIO_PREFIX0_AP0_Msk;
  NRF_RADIO->BASE0 = access_address << 8;
  NRF_RADIO->CRCINIT = crc_init;
  // enable receiver
  NRF_RADIO->EVENTS_READY = 0;
  NRF_RADIO->TASKS_TXEN = 1;

  /* From now, radio will send data and notify the result to Radio_IRQHandler */
}

/**
 * Change radio from TX to RX, while keeping last configuration of radio_send_custom or radio_set_sniff
 **/

void radio_tx_to_rx()
{
  NRF_RADIO->PACKETPTR = (uint32_t)(rx_buffer);
  NVIC_DisableIRQ(RADIO_IRQn);
  NRF_RADIO->SHORTS = RADIO_SHORTS_READY_START_Msk;

  // NRF_RADIO->INTENSET = 0;
  NVIC_ClearPendingIRQ(RADIO_IRQn);
  NVIC_EnableIRQ(RADIO_IRQn);

  NRF_RADIO->EVENTS_DISABLED = 0;
  NRF_RADIO->TASKS_DISABLE = 1;

  while (NRF_RADIO->EVENTS_DISABLED == 0)
    ;

  NRF_RADIO->EVENTS_READY = 0;
  NRF_RADIO->TASKS_RXEN = 1;
}