// System includes
#include <Adafruit_TinyUSB.h>
#include <Arduino.h>
#include <nrf_ppi.h>
// Project includes
#include "helpers.h"
#include "radio.h"
#include "sequence.h"
#include "timer.h"

#define VERSION_STRING "1.0.7"

#define SERIAL_BAUDRATE 115200 // UART baudrate

// #define BSP_LED_RED 12
// #define BSP_LED_GREEN 13
// #define BSP_LED_BLUE 22
#define BSP_LED_RED NRF_GPIO_PIN_MAP(0, 14)
#define BSP_LED_GREEN NRF_GPIO_PIN_MAP(0, 13)
#define BSP_LED_BLUE NRF_GPIO_PIN_MAP(0, 15)
#define BSP_SELF_PINRESET_PIN NRF_GPIO_PIN_MAP(0, 19)
#define CHANNEL_STARTUP NRF_GPIO_PIN_MAP(0, 16)
#define JAMMING_TRIGGER_PIN NRF_GPIO_PIN_MAP(1, 1)
#define CHANNEL_LED BSP_LED_GREEN

#define DEFAULT_ADV_ACCESS_ADDR 0x8E89BED6 // Default Access Address for advertiment channels (37-39)
#define DEFAULT_ADV_CRC_INIT 0x555555
#define DEFAULT_INITIAL_CHANNEL 39

#define MAX_PKT_RETRIES 50 // Maximum times to retry a packet if ack handling is enabled
#define MAX_REQUEST_TIME 2000
#define MAX_PKTS_IN 64 // Maximum packets in the queue
#define HEAD_PADDING 6

// Macros
#define led_ON(pin) digitalWrite(pin, 0)
#define led_OFF(pin) digitalWrite(pin, 1)

// ENUMs
enum SERIAL_COMMANDS {
    CMD_DATA_RX = 0xA7,                 // Used to receive or send packets in any radio channel
    CMD_DATA_TX = 0xBB,                 // Used to receive empty pdus that were automatically transmitted
    CMD_JAMMING = 0x66,                 // Enable or disable advertisement channels jamming (No device nearby can be discovered)
    CMD_FIFO_FULL = 0xA1,               // Indicates when tranmission data FIFO is full
    CMD_CHECKSUM_ERROR = 0xA8,          // Indicates serial reception error.
    CMD_CONFIG_AUTO_EMPTY_PDU = 0xA9,   // Not Used
    CMD_CONFIG_ACK = 0xAA,              // Not used
    CMD_CONFIG_LOG_TX = 0xCC,           // Enable handling of SN and NESN and auto retransmission
    CMD_CONFIG_SN_NESN = 0xAD,          // Set SN and NESN bits during anchor point
    CMD_BOOTLOADER_SEQ1 = 0xA6,         // Command to reset board into bootloader (sequence 1/2)
    CMD_BOOTLOADER_SEQ2 = 0xC7,         // Command to reset board into bootloader (sequence 2/2)
    CMD_LOG = 0x7F,                     // Print logs through python driver library
    CMD_VERSION = 0xB0,                 // Used to receive firmaware version string
    CMD_CONNECTION_STATUS = 0xB1,       // Used to receive firmaware connection status
    CMD_SET_SCAN_MODE = 0xB2,           // Used to set firmware to scan mode
    CMD_SET_BDADDR = 0xB3,              // Set BLE BDADDRESS
    CMD_SET_BLE_ROLE = 0xB4,            // Set BLE role (Central (0), Peripheral (1), Impersonator (2))
    CMD_SET_AUTO_DISCONNECT = 0xB5,     // Set auto disconnection if connection times out
    CMD_SET_STOP_PKT_FORWARDING = 0xB6, // Stop forwarding packets to the host
    CMD_SET_FORCE_CHANNEL = 0xB7        // Forcebly BLE change channel
};

enum BLE_RADIO_MODE {
    // Radio Modes
    RADIO_MODE_ADV = 0,
    RADIO_MODE_DATA = 1
};

enum BLE_ROLES {
    // Roles
    ROLE_CENTRAL = 0,
    ROLE_PERIPHERAL = 1,
    ROLE_IMPERSONATOR = 2,
};

enum BLE_ADV_TYPES {
    //  Advertising channel PDU Header’s PDU Type field encoding
    BLE_ADV_IND = 0x00,           // Not used
    BLE_ADV_DIRECT_IND = 0x01,    // Not used
    BLE_ADV_NONCONN_IND = 0x02,   // Not used
    BLE_ADV_SCAN_REQUEST = 0x03,  // Used
    BLE_ADV_SCAN_RESPONSE = 0x04, // Not used
    BLE_ADV_CONNECT_REQ = 0x05,   // Used
    BLE_ADV_SCAN_IND = 0x06,      // Not used
};

enum BLE_DATA_LLID_TYPES {
    //  LLIDs of data frames
    LL_DATA_PDU_FRAGMENT = 0x01, // Used (only to send empty PDUs)
    LL_DATA_PDU_START = 0x02,    // Not used
    LL_CONTROL_PDU = 0x03,       // Used
};

enum BLE_DATA_CONTROL_TYPES {
    //  Opcodes of control LLID data PDUs
    LL_CONNECTION_UPDATE_REQ = 0x00, // Used
    LL_CHANNEL_MAP_REQ = 0x01,       // Used
    LL_TERMINATE_IND = 0x02,         // Not used
    LL_ENC_REQ = 0x03,               // Not used
    LL_ENC_RSP = 0x04,               // Not used
    LL_START_ENC_REQ = 0x05,         // Not used
    LL_START_ENC_RSP = 0x06,         // Not used
};

// Variables
uint8_t *rx_buffer;
uint8_t *tx_buffer;
uint8_t *current_tx_buffer = nullptr;
uint8_t txt_buffer[32];
uint8_t ble_role = ROLE_IMPERSONATOR;

uint8_t flag_bcc = 0;
uint8_t flag_tx = 0;
uint8_t flag_addr_matched = 0;
uint64_t flag_toggle_led_tx = 0;

// Radio variables
uint8_t radio_channel;
uint32_t radio_access_address;
uint32_t radio_crc_init;
volatile uint8_t radio_data_mode = 0;            // Enable data channel hopping
volatile uint8_t radio_connection_requested = 0; // Notify when a connection is requested
uint8_t radio_data_enable_ack_flags = 1;         // Handle data header flags for SN and NESN and auto retransmission
uint8_t radio_data_enable_auto_empty_pdu = 1;    // Auto send empty pdu during each connection event
uint8_t radio_data_tx_log_enable = 0;            // Log transmitted data back (useful to check what sn/nesn is used)
uint8_t radio_auto_disconnect = 0;               // Auto disconnect after connection timeout (otherwise keeps hopping)
uint8_t initial_SN = 0;
uint8_t initial_NESN = 0;
volatile uint8_t radio_data_SN = 0;                    // Sequence Number (Master updates)
volatile uint8_t radio_data_NESN = 0;                  // Next Expected Sequence Number (Slave computes)
volatile uint8_t radio_data_stop_pkt_forwarding = 0;   // Disable packet forwading to the host
volatile uint8_t radio_data_skip_retry_forwarding = 1; // Do not forward retried packet to the host
volatile uint64_t radio_data_rx_timeout_ms = 100;

// Connection flags
volatile uint8_t wait_end_of_conn_req = 0; // Indicate when to initiate connection window
volatile uint8_t data_to_ack = 0;
volatile uint8_t data_to_ack_retries = 0;
volatile int32_t conn_event_counter = 0;
volatile uint8_t connection_update_requested = 0;
volatile uint8_t channel_update_requested = 0;
volatile uint32_t connetion_last_time;
volatile uint32_t last_conn_interval = 0;
SequenceGenerator channel_sequence;

// Variables for Packet handling
uint8_t wait_buffer[16];
volatile uint8_t wait_buffer_len = 0;
volatile uint8_t wait_buffer_offset;
volatile uint8_t transmitting = 0;
volatile uint8_t packet_received = 0;
volatile uint8_t packet_received_size = 0;
volatile uint8_t packet_transmitted = 0;

// Misc
static uint8_t log_buffer[32];
static uint8_t led_status = 1;

// Advertisement address buffer
static uint8_t adv_address[] = {0x22, 0xf5, 0xeb, 0x2a, 0x03, 0xa8};

// Empty PDU packet used to ACKs
static uint8_t pkt_empty_pdu[] = {0x00, 0x00, 0x00, 0x00, 0xd, 0x0, 0x00, 0x00, 0x00};

// Scan Response packet
uint8_t pkt_scan_response[] = {0x4, 0x1b, 0xbe, 0xb5, 0x19,
                               0xc4, 0xf5, 0xfc, 0x2, 0x1, 0x6, 0x8, 0x9,
                               0x4d, 0x79, 0x45, 0x53, 0x50, 0x33, 0x32, 0x2,
                               0xa, 0xeb, 0x5, 0x12, 0x20, 0x0, 0x40, 0x0,
                               0xf5, 0xf5, 0xb};

struct __attribute__((packed)) ble_packets_structure {
    uint16_t size[MAX_PKTS_IN];
    uint8_t *pkt_buffer[MAX_PKTS_IN];
    uint8_t idx = 0;
} ble_packets;

// Main structure used during connection Master <-> Slave connection
// Received when BLE_ADV_CONNECT_REQ PDU is receiveed via serial
struct __attribute__((packed)) connection_parameters {
    uint32_t access_address;
    uint32_t crc_init : 24;
    uint8_t window_size;
    uint16_t window_offset;
    uint16_t interval;
    uint16_t latency;
    uint16_t timeout; // Supervision Timeout not taken into account
    uint8_t channel_map[5];
    uint8_t hop_increment : 5;
    uint8_t sca : 3; // SCA - Sleep clock accuracy not taken into account
} connection;

struct __attribute__((packed)) connection_update_parameters {
    uint8_t window_size;
    uint16_t window_offset;
    uint16_t interval;
    uint16_t latency;
    uint16_t timeout;
    uint16_t instant; // instant is compared with conn_event_counter if a connection update is sent
} connection_update;

struct __attribute__((packed)) channel_update_parameters {
    uint8_t channel_map[5];
    uint16_t instant;
} channel_update;

struct __attribute__((packed)) connection_status_structure {
    uint8_t radio_data_mode : 1;
    uint8_t data_to_ack : 1;
    uint8_t data_to_ack_retries : 3;
    uint8_t radio_connection_requested : 1;
    uint8_t wait_end_of_conn_req : 1;
    uint8_t wait_buffer_len : 1;
} connection_status;

static inline void toggle_status_led(uint32_t d_time = 500000)
{
    nrf_gpio_pin_write(CHANNEL_LED, 0);
    flag_toggle_led_tx = micros() + d_time;
}

/**
 * wait_bytes_in_radio
 *
 * Answer a frame after certain bytes contained within the sent packet
 **/
static inline void wait_bytes_in_radio(uint8_t *buffer, uint8_t src_offset, uint8_t dst_offset, uint8_t len)
{
    for (uint8_t i = 0; i < len; i++) {
        wait_buffer[i] = buffer[i + src_offset];
    }

    wait_buffer_offset = dst_offset;
    wait_buffer_len = len;
}

/**
 * check_bytes_in_radio
 *
 * Check if bytes are present in received packet
 **/
static inline uint8_t check_bytes_in_radio()
{

    if (wait_buffer_len) {
        uint8_t len = wait_buffer_len;

        for (uint8_t i = 0; i < len; i++) {
            if (wait_buffer[i] != rx_buffer[i + wait_buffer_offset])
                return 0;
        }
        wait_buffer_len = 0;
        led_OFF(BSP_LED_BLUE);
        return 1;
    }
    return 0;
}

static inline uint8_t check_bdaddr(uint8_t *buf1, uint8_t *buf2)
{
    // Check if buf1 and buf2 has the same 6 bytes of bdaddr
    return ((*(uint32_t *)buf1 == *(uint32_t *)buf2)) &&           // Compare first 4 bytes
           ((*(uint16_t *)(buf1 + 4) == *(uint16_t *)(buf2 + 4))); // Compare last 2 bytes
}

/* Serial low level functions */
static inline void uart_write_data_rx(uint8_t *src_array, uint16_t src_len)
{
    int32_t c_event_counter;
    uint8_t checksum = 0;
    uint16_t i;

    if (conn_event_counter < 0)
        c_event_counter = 0;
    else
        c_event_counter = conn_event_counter;

    src_array -= HEAD_PADDING; // for cmd + length
    src_array[0] = CMD_DATA_RX;
    src_array[1] = src_len & 0xFF;
    src_array[2] = src_len >> 8;
    src_array[3] = c_event_counter;
    src_array[4] = c_event_counter >> 8;
    src_array[5] = radio_channel;
    src_array += HEAD_PADDING;

    for (i = 0; i < src_len; i++) {
        checksum += src_array[i];
    }
    src_array[i] = checksum;
    Serial.write(src_array - HEAD_PADDING, HEAD_PADDING + src_len + 1);
}

static inline void uart_write_data_tx(uint8_t *src_array, uint16_t src_len)
{
    int32_t c_event_counter;
    uint8_t checksum = 0;
    uint16_t i;

    if (conn_event_counter < 0)
        c_event_counter = 0;
    else
        c_event_counter = conn_event_counter;

    src_array -= HEAD_PADDING; // for cmd + length
    src_array[0] = CMD_DATA_TX;
    src_array[1] = src_len & 0xFF;
    src_array[2] = src_len >> 8;
    src_array[3] = c_event_counter;
    src_array[4] = c_event_counter >> 8;
    src_array[5] = radio_channel;
    src_array += HEAD_PADDING;

    for (i = 0; i < src_len; i++) {
        checksum += src_array[i];
    }
    src_array[i] = checksum;
    Serial.write(src_array - HEAD_PADDING, HEAD_PADDING + src_len + 1);
}

static inline void uart_log(String str)
{
    uint16_t len = str.length();
    log_buffer[0] = CMD_LOG;
    log_buffer[1] = len & 0xFF;
    log_buffer[2] = len >> 8;

    Serial.write(log_buffer, 3);
    Serial.print(str);
}

static inline void change_adv_channel()
{
    // Don't change adv channel in data mode
    if (transmitting == 0) {
        nrf_gpio_pin_write(CHANNEL_LED, led_status);
        led_status = !led_status;

        radio_channel += 1;
        if (radio_channel > 39) {
            radio_channel = DEFAULT_INITIAL_CHANNEL;
        }

        radio_set_sniff(radio_channel, radio_access_address);
    }
}

static inline void change_data_channel_peripheral()
{
    static uint8_t update_timer_on_next_evt = 0;

    // Increment event counter every channel hop
    conn_event_counter += 1;

    // if LL_CONNECTION_UPDATE_IND is received
    if (connection_update_requested && (conn_event_counter == (connection_update.instant))) {
        connection_update_requested = 0;
        connection.interval = connection_update.interval;
        connection.window_offset = connection_update.window_offset;
        connection.timeout = connection_update.timeout;

        if (connection.window_offset) {
            update_timer_on_next_evt = 1;
            timer4_update((connection.window_offset * 1250) - 1000); // if window_offset > 0
        }
        else
            timer4_update(((connection.interval * 1250) - 1000)); // if window_offset = 0
    }
    // if LL_CHANNEL_UPDATE_IND is received
    if (channel_update_requested && (conn_event_counter == (channel_update.instant))) {
        channel_update_requested = 0;
        channel_sequence.updateChannelMap(channel_update.channel_map);
    }

    // Update timer back to interval if connection update is received in the previous event (instant)
    if (update_timer_on_next_evt) {
        update_timer_on_next_evt = 0;
        timer4_update(((connection.interval * 1250) - 1000));
    }

    // Update radio parameters
    radio_channel = channel_sequence.getNextChannel();
    radio_access_address = connection.access_address;
    radio_crc_init = connection.crc_init;
    radio_set_sniff_peripheral(radio_channel, radio_access_address, radio_crc_init); // Change channel of peripheral
}

static inline void IRQ_peripheral()
{
    // Handle Advertisement Channel Reception
    if (radio_data_mode == RADIO_MODE_ADV) {
        if (check_bdaddr(rx_buffer + 8, adv_address)) {
            packet_received = 1; // Only recieve packets from central

            // Check if we are the peripheral and reply scan requests
            // LL Scan Request
            if ((ble_role == ROLE_PERIPHERAL) && ((rx_buffer[0] & 0xF) == 3)) {
                delayMicroseconds(88); // Aproximatelly 150us
                // Copy contents from scan response buffer to tx_buffer
                memcpy(tx_buffer, pkt_scan_response, sizeof(pkt_scan_response));
                transmitting = 1;
                radio_send_custom(tx_buffer, radio_channel, radio_access_address, radio_crc_init);
            }

            // LL Connection Request
            if ((rx_buffer[0] & 0xF) == 5) {
                // Copy contents of the buffer to connection struct
                memcpy((void *)&connection, (void *)&rx_buffer[14], 22);
                // Peripheral starts RX a bit earlier in data channel to receive achor point
                timer4_start(change_data_channel_peripheral, (connection.window_offset * 1250) - 100);

                // Initialize radio params
                // Update last connection time
                connetion_last_time = micros();
                conn_event_counter = -1;
                radio_data_mode = RADIO_MODE_DATA;
                radio_data_SN = initial_SN;     // Reset SN
                radio_data_NESN = initial_NESN; // Reset NESN

                // Prepare channel sequence generator to follow connection
                channel_sequence.initialize(connection.channel_map);
                channel_sequence.setHopIncrement(connection.hop_increment); // This is to set Hop Increment.
                channel_sequence.resetConnection();
            }
        }
    }
    // Handle Data Channel Reception
    else if (radio_access_address != DEFAULT_ADV_ACCESS_ADDR) {

        NRFX_DELAY_US(87); // Aproximatelly 150us <-- Gotta Change this

        // Read ACK bits from received packet
        uint8_t received_NESN = bitRead(rx_buffer[0], 2);
        uint8_t received_SN = bitRead(rx_buffer[0], 3);
        packet_received = 1;    // Flag to indicate we have received a data or empty pdu
        packet_transmitted = 1; // Flag to indicate we have transmitted a data or empty pdu

        // static uint8_t retry = 0;
        static volatile uint8_t last_data_to_ack = 0;

        // Handle retry logic
        if (received_SN == radio_data_NESN) {
            // Previous packet has been acknowledged (previous nesn == current sn)
            if (last_data_to_ack != data_to_ack) {
                data_to_ack_retries = 0;
            }
            else if (last_data_to_ack) {
                data_to_ack = 0;
                last_data_to_ack = 0;
            }
            last_data_to_ack = data_to_ack;
        }
        else {
            last_data_to_ack = data_to_ack;
            // Previous packet has not been acknowledged (previous nesn != current sn)
            if (radio_data_skip_retry_forwarding) {
                // TODO: check if this is working (possibly corner case)
                packet_received = 0;
                packet_transmitted = 0;
            }
            if (data_to_ack_retries++ >= MAX_PKT_RETRIES) {
                data_to_ack = 0;
                last_data_to_ack = 0;
                data_to_ack_retries = 0;
            }
        }

        // Select buffer to transmit based on data_to_ack (retry logic)
        if (data_to_ack)
            current_tx_buffer = tx_buffer; // reuse tx_buffer for retransmission
        else
            current_tx_buffer = pkt_empty_pdu + 4; // Data has been correctly transmitted, switch to empty PDU

        if (!conn_event_counter) {
            radio_data_SN = received_SN;
            radio_data_NESN = !received_SN;
        }
        else {
            // Peripheral toggles nesn while master repeats it
            radio_data_SN = received_NESN;
            radio_data_NESN = !received_NESN;
        }

        bitWrite(current_tx_buffer[0], 4, 0);
        bitWrite(current_tx_buffer[0], 3, radio_data_SN);
        bitWrite(current_tx_buffer[0], 2, radio_data_NESN);

        transmitting = 1;
        radio_send_custom(current_tx_buffer, radio_channel, radio_access_address, connection.crc_init);

        // Update timer when anchor point is received
        // if (!conn_event_counter)
        timer4_update(((connection.interval * 1250) - 800));

        if (((rx_buffer[0] & 0x03) == LL_CONTROL_PDU) && (rx_buffer[2] == LL_CONNECTION_UPDATE_REQ)) {
            // Copy the parameters to connection_update
            memcpy((void *)(&connection_update), (void *)(&rx_buffer[3]), 11);
            connection_update_requested = 1;
        }

        // This was added.
        if (((rx_buffer[0] & 0x03) == LL_CONTROL_PDU) && (rx_buffer[2] == LL_CHANNEL_MAP_REQ)) {
            // Copy the parameters to channel_update
            memcpy((void *)(&channel_update), (void *)(&rx_buffer[3]), sizeof(channel_update));
            channel_update_requested = 1;
        }

        // Toggle LED to indicate reception from master
        connetion_last_time = millis();
        nrf_gpio_pin_write(CHANNEL_LED, led_status);
        led_status = !led_status;
    }
}

volatile uint8_t flag_jamm = 0;

/**
 * nRF51822 RADIO handler.
 *
 * This handler is called whenever a RADIO event occurs (IRQ).
 **/
extern "C" void RADIO_IRQHandler(void)
{

    if (NRF_RADIO->EVENTS_READY) {
        // Clear event READY just in case HW didn't clear it
        NRF_RADIO->EVENTS_READY = 0;
    }

    // ---------- 2. Save connection structure and JAM current packet by switching to TX mode --------------
    if (flag_addr_matched) {
        flag_addr_matched = 0; // Clear addr matching flag
        nrf_gpio_pin_write(FEM_RXEN, 0);
        nrf_gpio_pin_write(FEM_TXEN, 1);
        // Enable TX (Goes from RX IDLE to TX Rampup)
        // NRF_RADIO->TASKS_STOP = 1;
        // NRF_RADIO->TASKS_TXEN = 1;
        NRF_P1->OUTCLR = (1 << 1);
        NRF_RADIO->SHORTS = RADIO_SHORTS_READY_START_Msk;
        NRF_RADIO->EVENTS_BCMATCH = 0;                      // Clear BCMATC event
        transmitting = 1;                                   // Indicate that next interrupt will be a transmission
        nrf_ppi_channel_disable(NRF_PPI, NRF_PPI_CHANNEL0); // Disable PPI
        toggle_status_led();                                // Toggle TX Led
        flag_jamm = 1;
        goto RX_CRC_CHECK_OK;
    }
    // -------------- 1. Check packet type and advertising address (peripheral) --------------
    if (NRF_RADIO->EVENTS_BCMATCH) {
        // We just stopped in the middle of the over-the-air packet to check its advertising address
        NRF_RADIO->EVENTS_BCMATCH = 0;
        // Check for advertising address that matches to the peripheral we want
        if (!radio_data_mode && !flag_addr_matched && ((rx_buffer[0] & 0b111) == 5) && (rx_buffer[1] == 34) && check_bdaddr(rx_buffer + 8, adv_address)) {
            // Set bit counter to channel hop increment offset. We will JAM when we reach that offset via PPI
            NRF_RADIO->BCC = 112 + 88 + 16 + 16 + 16 + (4 * 8) + 8;
            // Indicate that we received a packet destined to our peripheral
            memset(&rx_buffer[15], 0, 21);
            flag_addr_matched = 1;
            // Enable TX on bitcounter via PPI
            NRF_RADIO->SHORTS = RADIO_SHORTS_READY_START_Msk;
            nrf_ppi_channel_enable(NRF_PPI, NRF_PPI_CHANNEL0);
        }
    }
    // -------------- 3. Stop transmission and switch to RX Mode ------------------------------
    else if (NRF_RADIO->EVENTS_END) {
        NRF_RADIO->EVENTS_END = 0;

        if (transmitting) {
            // Switch Radio mode from TX to RX
            transmitting = 0;
            // radio_tx_to_rx(!radio_data_mode);
            radio_tx_to_rx(!radio_data_mode);
            // TX IRQ ends here
            return;
        }

        // If CRC is valid
        if (NRF_RADIO->CRCSTATUS) {
        RX_CRC_CHECK_OK:
            // access address (4B) + header (2B) + payload (rx_buffer[1]B)
            uint16_t sz = ((rx_buffer[1] & 0b11111111) + 2);
            if (sz > 255) {
                return;
            }
            uint32_t crc = NRF_RADIO->RXCRC;
            // Adding crc to the end of RX buffer.
            rx_buffer[sz] = crc;
            rx_buffer[sz + 1] = crc >> 8;
            rx_buffer[sz + 2] = crc >> 16;
            sz += 4 + 3; // Access Address (4 Bytes) + CRC (3 Bytes)
            packet_received_size = sz;

            IRQ_peripheral();
        }
    }
}

static inline void start_scanning(uint8_t enable_autoscan = 0, uint8_t initial_channel = DEFAULT_INITIAL_CHANNEL)
{
    /* Sniffer is idling. */
    timer4_stop();
    conn_event_counter = 0;
    radio_data_mode = RADIO_MODE_ADV; // Disable data mode
    radio_access_address = DEFAULT_ADV_ACCESS_ADDR;
    radio_crc_init = DEFAULT_ADV_CRC_INIT;
    radio_channel = DEFAULT_INITIAL_CHANNEL;
    /* Start sniffing BLE packets on channel 37. */
    radio_set_sniff(radio_channel, radio_access_address);

    // Start scheduling advertisement channel changing (37-39)
    // This is commented -> Chaning channels every 25000ms
    // timer4_start(change_adv_channel, 250000UL);

    led_OFF(BSP_LED_GREEN);
    led_OFF(BSP_LED_RED);
    led_OFF(BSP_LED_BLUE);
    nrf_gpio_pin_write(CHANNEL_LED, 1);
}

static inline void handle_adv_pkt()
{
    uint8_t pdu_type = tx_buffer[0] & 0x0F;

    if (radio_data_mode || data_to_ack) {
        radio_data_mode = RADIO_MODE_ADV;
        data_to_ack = 0;
        radio_connection_requested = 0;
        wait_end_of_conn_req = 0;
        wait_buffer_len = 0;
        start_scanning();
    }

    if (pdu_type == BLE_ADV_SCAN_REQUEST) {
        // Source Offset to compare: header (2B) + scanning addr (6B) = 8 (advertising addr)
        // Receiver packet Offset to compare: header (2B) = 2 (advertising addr)

        wait_bytes_in_radio(tx_buffer, 8, 2, 6); // Wait a packet from the target advertising address
        led_ON(BSP_LED_BLUE);
    }
    else if (pdu_type == BLE_ADV_CONNECT_REQ) {
        timer4_stop();
        memcpy((void *)&connection, (void *)&tx_buffer[14], 22);

        wait_bytes_in_radio(tx_buffer, 8, 2, 6); // Wait a packet from the target advertising address
        if (connection.interval) {
            radio_connection_requested = 1; // Enable data mode (channel hopping will begin once after connect request is sent to the link slave)
            connetion_last_time = millis();
            led_ON(BSP_LED_BLUE);
        }
    }
    else {

        if (pdu_type == BLE_ADV_IND || pdu_type == BLE_ADV_NONCONN_IND || pdu_type == BLE_ADV_DIRECT_IND) {
            // Change role to peripheral automatically upon reception of
            ble_role = ROLE_PERIPHERAL;
            // Copy advertisement address to internal adv_address
            memcpy(adv_address, tx_buffer + 2, 6);
        }

        transmitting = 1;
        radio_send_custom(tx_buffer, radio_channel, radio_access_address, radio_crc_init);
        toggle_status_led(100);
    }
}

static inline void handle_data_pkt()
{
    uint8_t llid = tx_buffer[0] & 0x03;

    if (ble_role == ROLE_CENTRAL && llid == LL_CONTROL_PDU) {
        uint8_t opcode = tx_buffer[2];
        // TODO: Place checks here to not handle invalid connection or channel map updates (used to verify if other device process them)
        switch (opcode) {
        case LL_CONNECTION_UPDATE_REQ:
            memcpy((void *)(&connection_update), (void *)(&tx_buffer[3]), 11); // Copy the parameters to connection_update
            connection_update_requested = 1;
            break;
        case LL_CHANNEL_MAP_REQ:
            memcpy((void *)&channel_update, (void *)&tx_buffer[3], 7); // Copy the parameters to channel_update
            channel_update_requested = 1;
            break;
        }
    }

    if (radio_data_mode) // Wait to send data packets only when radio is connected
    {
        data_to_ack = 1;
        data_to_ack_retries = 0;
    }
}

void setup()
{
    // Configure LED RED as OFF
    nrf_gpio_cfg_output(BSP_LED_RED);
    nrf_gpio_pin_set(BSP_LED_RED);

    // Configure LED GREEN as OFF
    nrf_gpio_cfg_output(BSP_LED_GREEN);
    nrf_gpio_pin_set(BSP_LED_GREEN);

    // Configure LED BLUE as OFF
    nrf_gpio_cfg_output(BSP_LED_BLUE);
    nrf_gpio_pin_set(BSP_LED_BLUE);

    // Configure channel indication LED
    nrf_gpio_cfg_output(CHANNEL_LED);
    nrf_gpio_pin_write(CHANNEL_LED, 1);

    // Configure Startup indication LED
    nrf_gpio_cfg_output(CHANNEL_STARTUP);
    nrf_gpio_pin_write(CHANNEL_STARTUP, 0);

    // Configure P019, pin tied to reset
    nrf_gpio_cfg_output(BSP_SELF_PINRESET_PIN);
    nrf_gpio_pin_set(BSP_SELF_PINRESET_PIN);

    // Config Jamming OUT pin (NOT USED)
    nrf_gpio_cfg_output(JAMMING_TRIGGER_PIN);
    nrf_gpio_pin_clear(JAMMING_TRIGGER_PIN);

    // Configure Signal booster pins (nRF21540)
    int fem_pin = FEM_RXEN;
    nrf_gpio_cfg_output(fem_pin);
    nrf_gpio_pin_write(fem_pin, 0);

    fem_pin = FEM_TXEN;
    nrf_gpio_cfg_output(fem_pin);
    nrf_gpio_pin_write(fem_pin, 0);

    fem_pin = FEM_MODE;
    nrf_gpio_cfg_output(fem_pin);
    nrf_gpio_pin_write(fem_pin, 0); // 0 - 20dbm, 1 - 10dbm

    fem_pin = FEM_ANTSEL;
    nrf_gpio_cfg_output(fem_pin);
    nrf_gpio_pin_write(fem_pin, 0); // Antenna 1 enabled

    fem_pin = FEM_PDN;
    nrf_gpio_cfg_output(fem_pin);
    nrf_gpio_pin_write(fem_pin, 1);

    fem_pin = FEM_CS;
    nrf_gpio_cfg_output(fem_pin);
    nrf_gpio_pin_write(fem_pin, 0);

    // Configure Serial
    Serial.begin(SERIAL_BAUDRATE);
    Serial.setTimeout(10);

    // Initialize rx and tx buffer
    rx_buffer = (uint8_t *)malloc(260 + 3 + 4);
    rx_buffer += HEAD_PADDING + 4; // 5 + 4 bytes padding (uart header + access address)
    tx_buffer = (uint8_t *)malloc(260 + 3 + 4);
    tx_buffer += HEAD_PADDING + 4; // 5 + 4 bytes padding (uart header + access address)

    // Configure PPI channels
    nrf_ppi_channel_and_fork_endpoint_setup(NRF_PPI,
                                            NRF_PPI_CHANNEL0,
                                            (uint32_t) & (NRF_RADIO->EVENTS_BCMATCH),
                                            (uint32_t) & (NRF_RADIO->TASKS_STOP),
                                            (uint32_t) & (NRF_RADIO->TASKS_TXEN));

    /* Put Radio in scanning mode */
    start_scanning(1);
}

static inline void handle_uart_packet_rx()
{
    // If a packet is received in Radio Interrupt
    if (packet_received && !radio_data_stop_pkt_forwarding) {
        uart_write_data_rx(rx_buffer - 4, packet_received_size); // Send packets via USB Serial
        packet_received = 0;
    }
}

static inline void handle_uart_packet_tx()
{
    if ((packet_received) ||
        (!radio_data_tx_log_enable) ||
        (!packet_transmitted) ||
        (radio_data_stop_pkt_forwarding))
        return;

    uint8_t *p_buf = current_tx_buffer;

    if (p_buf == pkt_empty_pdu + 4) // If current_tx_buffer is not pointing to tx_buffer
    {
        *((uint32_t *)(p_buf - 4)) = radio_access_address; // Write access address
    }

    uint8_t tx_len = 4 + 2 + p_buf[1] + 3; // Access Address + header + pkt + crc
    // Adding crc to the end of TX buffer.
    uart_write_data_tx(p_buf - 4, tx_len); // Send transmitted packet via USB Serial
    packet_transmitted = 0;
}

static inline void handle_connection_timeout()
{
    if (radio_data_mode == RADIO_MODE_DATA) {
        uint64_t time = millis();
        if ((time - connetion_last_time) >= radio_data_rx_timeout_ms) {
            if (radio_auto_disconnect) {
                start_scanning();
            }
            else {
                led_OFF(BSP_LED_GREEN);
                led_ON(BSP_LED_RED);
            }
        }
    }
}

static inline void handle_ble_packet_queue()
{
    while (ble_packets.idx && !data_to_ack && !transmitting) {
        memcpy(tx_buffer - 4, ble_packets.pkt_buffer[0], ble_packets.size[0] + 4); // Copy also access address to offset -4
        free(ble_packets.pkt_buffer[0]);
        // Shift all buffer pointers toward index 0
        for (uint8_t i = 0; i < ble_packets.idx - 1; i++) {
            ble_packets.pkt_buffer[i] = ble_packets.pkt_buffer[i + 1];
            ble_packets.size[i] = ble_packets.size[i + 1];
        }

        // Get a pointer to tx_buffer, but 4 positions earlier to get access address (aa)
        uint32_t *aa = (uint32_t *)(tx_buffer - 4);

        if (*aa == DEFAULT_ADV_ACCESS_ADDR)
            handle_adv_pkt(); // Handler adv packet according to PDU Type
        else {
            handle_data_pkt();
        }

        ble_packets.idx--;
    }
}

static inline void handle_uart_commands_rx()
{
    while (Serial.available()) // If computer sent packet via USB Serial
    {
        uint8_t cmd;
        uint16_t cmd_len;
        uint8_t checksum;

        cmd = Serial.read();

        switch (cmd) // Check first byte for command
        {
        case CMD_DATA_TX: // All data commands is to be sent via BLE Radio
        {
            Serial.readBytes((uint8_t *)&cmd_len, 2); // Get data length

            if (cmd_len >= 270)
                continue;

            uint8_t *work_buffer = (uint8_t *)malloc(4 + cmd_len + 1); // Get aa (4B) + data (tx_buffer) + Checksum (1B)
            Serial.readBytes(work_buffer, cmd_len + 1);

            // Calculate checksum
            checksum = 0;
            for (int16_t i = 0; i < cmd_len; i++) {
                checksum += work_buffer[i];
            }
            // Verify received checksum against calculated checksum
            if (checksum == work_buffer[cmd_len]) {
                // uart_log(String(ble_packets.idx));
                if (ble_packets.idx <= MAX_PKTS_IN) {
                    ble_packets.size[ble_packets.idx] = cmd_len;
                    ble_packets.pkt_buffer[ble_packets.idx] = work_buffer;
                    ble_packets.idx = ble_packets.idx + 1;
                }
                else {
                    free(work_buffer);
                    Serial.write(CMD_FIFO_FULL);
                }
            }
            else {
                // If a error is received, send a checksum error so the host can retransmit the packet;
                free(work_buffer);
                Serial.write(CMD_CHECKSUM_ERROR);
            }
            break;
        }

        case CMD_CONFIG_AUTO_EMPTY_PDU:
            Serial.readBytes(&radio_data_enable_auto_empty_pdu, 1);
            break;

        case CMD_CONFIG_ACK:
            Serial.readBytes(&radio_data_enable_ack_flags, 1);
            break;

        case CMD_CONFIG_LOG_TX:
            Serial.readBytes(&radio_data_tx_log_enable, 1);
            break;

        case CMD_SET_STOP_PKT_FORWARDING:
            Serial.readBytes((uint8_t *)&radio_data_stop_pkt_forwarding, 1);
            break;

        case CMD_SET_FORCE_CHANNEL:
            Serial.readBytes(&radio_channel, 1);
            timer4_stop();
            wait_buffer_len = 0;
            radio_data_mode = RADIO_MODE_ADV; // TODO: check channels and set correct mode
            data_to_ack = 0;
            wait_end_of_conn_req = 0;
            radio_connection_requested = 0;
            // Clear packet buffer
            while (ble_packets.idx)
                free(ble_packets.pkt_buffer[ble_packets.idx--]);

            start_scanning(0, radio_channel);
            break;

        case CMD_VERSION:
            Serial.write(CMD_VERSION);
            Serial.write(VERSION_STRING, sizeof(VERSION_STRING));
            break;

        case CMD_CONNECTION_STATUS:
            connection_status.data_to_ack = data_to_ack;
            connection_status.data_to_ack_retries = data_to_ack_retries;
            connection_status.radio_connection_requested = radio_connection_requested;
            connection_status.radio_data_mode = radio_data_mode;
            connection_status.wait_end_of_conn_req = wait_end_of_conn_req;
            connection_status.wait_buffer_len = wait_buffer_len;
            Serial.write(CMD_CONNECTION_STATUS);
            Serial.write((uint8_t *)&connection_status, sizeof(connection_status));
            break;

        case CMD_SET_SCAN_MODE:
            timer4_stop();
            wait_buffer_len = 0;
            radio_data_mode = RADIO_MODE_ADV;
            data_to_ack = 0;
            wait_end_of_conn_req = 0;
            radio_connection_requested = 0;
            // Clear packet buffer
            while (ble_packets.idx)
                free(ble_packets.pkt_buffer[ble_packets.idx--]);

            start_scanning(1);
            break;

        case CMD_SET_BDADDR:
            Serial.readBytes(adv_address, 6);
            memcpy(pkt_scan_response + 8, adv_address, 8);
            break;

        case CMD_SET_BLE_ROLE:
            Serial.readBytes(&ble_role, 1);
            break;

        case CMD_CONFIG_SN_NESN:
            uint8_t value;
            Serial.readBytes(&value, 1);
            initial_SN = value & 0b1;
            initial_NESN = (value >> 1) & 0b1;
            break;

        case CMD_SET_AUTO_DISCONNECT:
            Serial.readBytes(&radio_auto_disconnect, 1);
            break;

        // Bootloader sequence commands reboot the device in bootloader mode
        case CMD_BOOTLOADER_SEQ1:
            uint8_t seq;
            Serial.readBytes(&seq, 1);
            if (seq == CMD_BOOTLOADER_SEQ2) {
                NRF_POWER->GPREGRET = 0x57;
                nrf_gpio_pin_clear(BSP_SELF_PINRESET_PIN); // Reset MCU in Bootloader
                delayMicroseconds(100);
                NVIC_SystemReset();
            }
            break;
        }
    }
}

static inline void handle_leds()
{
    if (flag_toggle_led_tx) {
        if (millis() >= flag_toggle_led_tx) {
            flag_toggle_led_tx = 0;
            nrf_gpio_pin_write(CHANNEL_LED, 1);
        }
    }
}

void loop()
{
    handle_uart_packet_rx();
    handle_uart_packet_tx();
    handle_uart_commands_rx();
    handle_ble_packet_queue();
    handle_leds();
    handle_connection_timeout();
    if (flag_jamm) {
        flag_jamm = 0;
        uart_log("pjamm");
    }
}
