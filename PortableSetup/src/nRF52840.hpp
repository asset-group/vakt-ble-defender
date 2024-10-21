#pragma once

#include "vaktble.hpp"

#define NRF52840_UART_SYNC_RW               \
    lock_guard<mutex> lock(mutex_uart_cmd); \
    mutex_uart_cmd_read.lock(true);         \
    std::unique_lock<priority_mutex> lk(mutex_uart_cmd_read, std::adopt_lock);

#define NRF52840_UART_SYNC_W lock_guard<mutex> lock(mutex_uart_cmd)

#define NRF52840_WAIT_RESP_COND(__res, __res_len, __error_cond, __timeout_ms) \
    ({                                                                        \
        uint64_t __c_ms = millis();                                           \
        while ((millis() - __c_ms) < (__timeout_ms)) {                        \
            uart->read((uint8_t *)&__res, (__res_len));                       \
            if (!(__error_cond))                                              \
                break;                                                        \
        }                                                                     \
        (__error_cond);                                                       \
    })

// ENUMs
enum SERIAL_COMMANDS {
    CMD_DATA_RX = 0xA7,                    // Used to receive or send packets in any radio channel
    CMD_DATA_TX = 0xBB,                    // Used to receive empty pdus that were automatically transmitted
    CMD_JAMMING = 0x66,                    // Enable or disable advertisement channels jamming (No device nearby can be discovered)
    CMD_CONFIG_JAMMING_CONN_REQ = 0x67,    // Enable or disable jamming connection request
    CMD_FIFO_FULL = 0xA1,                  // Indicates when tranmission data FIFO is full
    CMD_CHECKSUM_ERROR = 0xA8,             // Indicates serial reception error.
    CMD_CONFIG_AUTO_EMPTY_PDU = 0xA9,      // Enable auto empty PDU response during connections (enabled by default)
    CMD_CONFIG_ACK = 0xAA,                 // Enable handling of SN and NESN and auto retransmission
    CMD_CONFIG_LOG_TX = 0xCC,              // Enable handling of SN and NESN and auto retransmission
    CMD_CONFIG_SN_NESN = 0xAD,             // Set SN and NESN bits during anchor point
    CMD_BOOTLOADER_SEQ1 = 0xA6,            // Command to reset board into bootloader (sequence 1/2)
    CMD_BOOTLOADER_SEQ2 = 0xC7,            // Command to reset board into bootloader (sequence 2/2)
    CMD_LOG = 0x7F,                        // Print logs through python driver library
    CMD_VERSION = 0xB0,                    // Used to receive firmaware version string
    CMD_CONNECTION_STATUS = 0xB1,          // Used to receive firmaware connection status
    CMD_CONFIG_SCAN_MODE = 0xB2,           // Used to set firmware to scan mode
    CMD_CONFIG_BDADDR = 0xB3,              // Set BLE BDADDRESS
    CMD_CONFIG_BLE_ROLE = 0xB4,            // Set BLE role (Central (0), Peripheral (1), Impersonator (2))
    CMD_CONFIG_AUTO_DISCONNECT = 0xB5,     // Set auto disconnection if connection times out
    CMD_CONFIG_STOP_PKT_FORWARDING = 0xB6, // Stop forwarding packets to the host
    CMD_CONFIG_FORCE_CHANNEL = 0xB7,       // Forcebly BLE change channel
    CMD_SELECTIVE_DATA_JAMMING = 0xB8      // Provide which bytes to jamm when matched in data channels
};

enum BLE_ROLES {
    // Roles
    ROLE_CENTRAL = 0,
    ROLE_PERIPHERAL = 1,
    ROLE_IMPERSONATOR = 2,
};

typedef struct __attribute__((packed)) _connection_status_t {
    uint8_t radio_data_mode : 1;
    uint8_t data_to_ack : 1;
    uint8_t data_to_ack_retries : 3;
    uint8_t radio_connection_requested : 1;
    uint8_t wait_end_of_conn_req : 1;
    uint8_t wait_buffer_len : 1;
} connection_status_t;

typedef struct __attribute__((packed)) _nordic_flags_t {
    uint8_t crc_ok : 1;    // (0 = Incorrect, 1 = OK)
    uint8_t direction : 1; // (0 = Slave -> Master, 1 = Master -> Slave)
    uint8_t encrypted : 1; // (0 = No, 1 = Yes)
    uint8_t mic_ok : 1;    // (0 = Incorrect, 1 = OK)
    uint8_t phy : 1;       //  (0 = 1M, 1 = 2M, 2 = Coded, rest unused)
    uint8_t rfu : 3;
} nordic_flags_t;

typedef struct __attribute__((packed)) _nordic_ble_hdr_t {
    uint8_t board_id;
    // Header Version 2
    uint16_t payload_length;
    uint8_t protocol_version;
    uint16_t packet_counter;
    uint8_t packet_id; // Aways EVENT_PACKET (ID 0x06)
    // Payload for Protocol Version 2
    uint8_t header_length; // Always 10
    nordic_flags_t flags;
    uint8_t channel;
    uint8_t rssi;
    uint16_t event_counter;
    uint32_t delta_time;

} nordic_ble_hdr_t;

typedef struct _driver_nrf52840_event_t {
    // Driver variables
    uint8_t evt;
    vector<uint8_t> data;
    uint16_t data_size;
    uint16_t event_counter;
    uint8_t channel;
    nordic_flags_t flags;
    uint16_t data_offset;
    uint8_t role;
    struct timespec timestamp_software;
    uint64_t pkt_counter;
    // User event variables
    string pkt_summary;
    bool pkt_save;
    struct timespec timestamp_user;
    bool pkt_valid;
} driver_nrf52840_event_t;

class nRF52840Driver {
private:
    // Debug options
    bool debug_rx_data = false;
    bool debug_tx_data = false;
    bool debug_rx_errors = false;

    std::mutex mutex_uart_cmd;
    priority_mutex mutex_uart_cmd_read;
    uint8_t ref_nordic_header[sizeof(nordic_ble_hdr_t)] = {0xa1, 0x2c, 0x0, 0x2, 0xca, 0xcb, 0x6, 0xa, 0x1,
                                                           0x25, 0x2c, 0x0, 0x0, 0x5f, 0x78, 0x0, 0x0};

    string discover_port_by_description(string description)
    {
        std::vector<serial::PortInfo> ports = serial::list_ports();

        for (auto &port : ports) {
            if (string_contains(port.description, "tty"))
                continue;

            if (!string_contains(port.description, description))
                continue;

            GL1Y("{}Found Port:{}\n\t   Desc.:{}\n\t   ID:{}",
                 TAG, port.port, port.description, port.hardware_id);
            return port.port;
        }

        return "";
    }

public:
    const char *TAG = "[nRF52840] ";
    serial::Serial *uart = nullptr;
    string serialport;
    int baudrate;
    bool is_open = false;
    bool ready = false;
    string fw_version;
    uint8_t role = ROLE_CENTRAL;
    uint64_t pkt_counter = 0;

    bool init(string serialport, int baudrate,
              int read_timeout_ms = 20,
              bool pooling = false,
              bool low_latency = false)
    {
        this->serialport = serialport;

        // If first paramater is not a serialport path, then we try to
        // discover the serial port path based on USB description
        if (!string_contains(serialport, "/")) {
            this->serialport = discover_port_by_description(serialport);
            if (!this->serialport.size()) {
                GL1R("{}Could not find serial port for \"{}\"", TAG, serialport);
                return false;
            }
        }

        this->baudrate = baudrate;
        try {
            GL1Y("{}Serial Port: {}", TAG, serialport);

            // Call fuser to forcebly kill any program using the same serial port
            system(fmt::format("fuser -k {}", this->serialport).c_str());
            // Open serial port
            this->uart = new serial::Serial(this->serialport,
                                            baudrate,
                                            serial::Timeout::simpleTimeout(read_timeout_ms), // Read timeout
                                            pooling,                                         // Enable pooling
                                            low_latency);                                    // Enable low latency (required)
            if (!(is_open = uart->isOpen())) {
                GL1R("{}Could not open port {}", TAG, this->serialport);
                close();
                return false;
            }
        }
        catch (const std::exception &e) {
            GL1R("{}Could not open port {}", TAG, this->serialport);
            close();
            return false;
        }

        GL1C("{}Checking Firmware...", TAG);
        // Stop any pkt forwarding
        set_stop_pkt_forwarding(1);
        this_thread::sleep_for(100ms);
        uart->flushInput();
        this_thread::sleep_for(100ms);
        uart->flushInput();

        // Check firmware version
        if (!(fw_version = get_version()).length()) {
            GL1R("{}Firmware version not detected", TAG);
            close();
            return false;
        }

        GL1G("{}Firmware version: {}", TAG, fw_version);

        connection_status_t *conn_status;
        if (!(conn_status = get_connecion_status())) {
            GL1R("{}Connection Status error", TAG);
            close();
            return false;
        }

        set_defaults();

        ready = true;
        return true;
    }

    string get_version()
    {
        if (unlikely(!uart))
            return "";

        NRF52840_UART_SYNC_RW;

        // Send version query command
        uint8_t cmd = CMD_VERSION;
        uart->flushInput();
        uart->write(&cmd, sizeof(cmd));

        uint8_t res;
        if (NRF52840_WAIT_RESP_COND(res, 1, res != cmd, 1000)) {
            GL1R("{}Couldn't get CMD_VERSION", TAG);
            return "";
        }

        // Get version string (6 bytes)
        string ret = uart->readline(6, "\n", false);

        if (string_contains(ret, ".")) {
            return ret;
        }

        return "";
    }

    connection_status_t *get_connecion_status()
    {
        static connection_status_t conn_status = {0};

        if (unlikely(!uart))
            return {NULL};

        NRF52840_UART_SYNC_RW;

        uint8_t cmd = CMD_CONNECTION_STATUS;
        uart->write(&cmd, 1);

        uint8_t res;
        if (NRF52840_WAIT_RESP_COND(res, 1, res != cmd, 1000)) {
            GL1R("{}Couldn't get CMD_CONNECTION_STATUS", TAG);
            return NULL;
        }

        uart->read((uint8_t *)&conn_status, sizeof(conn_status));

        return &conn_status;
    }

    driver_nrf52840_event_t receive()
    {
        uint8_t pcap_buff[256] = {0};
        nordic_ble_hdr_t *nordic_hdr = (nordic_ble_hdr_t *)pcap_buff;
        uint8_t *data_buff = pcap_buff + sizeof(nordic_ble_hdr_t);
        uint8_t cmd;
        uint16_t cmd_len;
        uint8_t checksum;
        uint16_t conn_evt_counter;
        uint8_t channel;
        struct timespec timestamp_software;

        while (ready) {
            // Lock read command mutex
            std::unique_lock<priority_mutex> lk(mutex_uart_cmd_read);

            if (uart->read(&cmd, 1) == 0)
                goto RX_END;

            switch (cmd) {
            case CMD_FIFO_FULL:
                GL1R("{}[{:X}] Fw: CMD_FIFO_FULL", TAG, cmd);
                break;
            case CMD_DATA_RX:
            case CMD_DATA_TX: {

                clock_gettime(CLOCK_MONOTONIC, &timestamp_software);

                // Receive payload length (not including connection event counter and channel) (2 Bytes)
                if (unlikely(uart->read((uint8_t *)&cmd_len, 2) != 2)) {
                    if (debug_rx_errors)
                        GL1R("{}[{:X}] Error getting length", TAG, cmd);
                    goto RX_END;
                }

                // Receive BLE event connection counter (2 Bytes)
                if (unlikely(uart->read((uint8_t *)&conn_evt_counter, 2) != 2)) {
                    if (debug_rx_errors)
                        GL1R("{}[{:X}] Error getting conn. event counter", TAG, cmd);
                    goto RX_END;
                }

                // Receive BLE channel  (1 Byte)
                if (unlikely(uart->read((uint8_t *)&channel, 1) != 1)) {
                    if (debug_rx_errors)
                        GL1R("{}[{:X}] Error getting channel", TAG, cmd);
                    goto RX_END;
                }

                // Check if length is lower than our data buffer
                if (unlikely(cmd_len > (sizeof(pcap_buff) - sizeof(nordic_ble_hdr_t)))) {
                    if (debug_rx_errors)
                        GL1R("{}[{:X}] data payload too big: {} > {}",
                             TAG, cmd, cmd_len, sizeof(data_buff));
                    goto RX_END;
                }

                // Receive payload + checksum (cmd_len + 1 Bytes)
                if (unlikely(uart->read(data_buff, cmd_len + 1) != cmd_len + 1)) {
                    if (debug_rx_errors)
                        GL1R("{}[{:X}] All data bytes ({}) not received", TAG, cmd, cmd_len);
                    goto RX_END;
                }

                // Calculate checksum
                checksum = 0;
                for (int16_t i = 0; i < cmd_len; i++) {
                    checksum += data_buff[i];
                }

                // Verify checksum
                if ((unlikely((checksum != data_buff[cmd_len])))) {
                    if (debug_rx_errors) {
                        vector<uint8_t> raw_data = vector<uint8_t>(data_buff, data_buff + cmd_len);
                        GL1R("{}[{:X}]Checksum Error. Calc:{:#X}, Recv:{:#X}", TAG, cmd, checksum, data_buff[cmd_len]);
                        GL1R("{}RX <-- {}", TAG, bytes_to_hex(data_buff, cmd_len + 1));
                    }
                    goto RX_END;
                }

                // Update nordic header (17 bytes)
                memcpy(pcap_buff, ref_nordic_header, sizeof(ref_nordic_header));
                nordic_hdr->channel = channel;
                nordic_hdr->event_counter = conn_evt_counter;
                if (this->role == ROLE_CENTRAL)
                    nordic_hdr->flags.direction = (cmd == CMD_DATA_RX ? 0 : 1); // TODO: detect driver role to solve this (0 = Slave -> Master, 1 = Master -> Slave)
                else
                    nordic_hdr->flags.direction = (cmd == CMD_DATA_RX ? 1 : 0);
                nordic_hdr->payload_length = nordic_hdr->header_length + cmd_len;

                // Create nordic_header + payload
                vector<uint8_t> data = vector<uint8_t>(pcap_buff, pcap_buff + sizeof(nordic_ble_hdr_t) + cmd_len);

                if (debug_rx_data)
                    GL1C("{}RX <-- {}", TAG, bytes_to_hex(&data[0], data.size()));

                return driver_nrf52840_event_t{cmd,
                                               move(data),
                                               cmd_len,
                                               conn_evt_counter,
                                               channel,
                                               nordic_hdr->flags,
                                               sizeof(nordic_ble_hdr_t),
                                               this->role,
                                               timestamp_software,
                                               ++this->pkt_counter};
                break;
            }
            case CMD_LOG: {
                if (uart->read((uint8_t *)&cmd_len, 2) != 2)
                    goto RX_END;

                if (uart->read(data_buff, cmd_len) != cmd_len)
                    goto RX_END;

                data_buff[cmd_len] = 0;

                GL1("{}FW Log:{}", TAG, (const char *)data_buff);
                break;
            }
            default:
                break;
            }

        RX_END:
            if (!(this->is_open = this->uart->isOpen()))
                ready = false;
        }

        return {NULL};
    }

    void send(const vector<uint8_t> &data, uint16_t offset = 0)
    {
        send((uint8_t *)&data[offset], data.size() - offset);
    }

    void send(uint8_t *src_array, uint16_t src_len)
    {
        static uint8_t uart_buffer[512];
        src_len -= 3; // Ignore 3 bytes from LL CRC
        uint16_t i = 0;
        uint16_t uart_pos = 0;
        uint16_t payload_len = src_len;
        uint8_t checksum = 0;

        if (unlikely(!uart && (src_len > (sizeof(uart_buffer) - 4)) && (src_len < 4))) {
            GL1R("{}Too few bytes to TX ({})", TAG, src_len);
            return;
        }

        NRF52840_UART_SYNC_W;

        uart_buffer[uart_pos++] = CMD_DATA_TX;
        uart_buffer[uart_pos++] = payload_len & 0xFF;
        uart_buffer[uart_pos++] = payload_len >> 8;

        // Serial Payload
        uint8_t *payload = uart_buffer + uart_pos;
        // LL Payload
        for (i = 0; i < src_len; i++) {
            payload[i] = src_array[i];
            checksum += payload[i];
        }
        payload[i] = checksum;

        // Write to serial
        uint16_t final_size = uart_pos + payload_len + 1;

        if (debug_tx_data)
            GL1C("{}({}) TX --> {}", TAG, role, bytes_to_hex(uart_buffer, final_size));

        uart->write(uart_buffer, final_size);
    }

    void set_defaults()
    {
        set_auto_disconnect(0);
        set_auto_empty_pdu(1);
        set_auto_ack(1);
        set_log_tx(0);
        set_scan_mode();
        set_stop_pkt_forwarding(0);
    }

    void set_sn_nesn(uint8_t value)
    {
        if (unlikely(!uart))
            return;

        NRF52840_UART_SYNC_W;

        // Send sn_nest command
        uint8_t cmd[] = {CMD_CONFIG_SN_NESN, value};
        uart->write(cmd, sizeof(cmd));
    }

    void set_jamm_conn_ind(uint8_t value)
    {
        if (unlikely(!uart))
            return;

        NRF52840_UART_SYNC_W;

        uint8_t cmd[] = {CMD_CONFIG_JAMMING_CONN_REQ, value};
        uart->write(cmd, sizeof(cmd));
    }

    void set_auto_disconnect(uint8_t value)
    {
        if (unlikely(!uart))
            return;

        NRF52840_UART_SYNC_W;

        uint8_t cmd[] = {CMD_CONFIG_AUTO_DISCONNECT, value};
        uart->write(cmd, sizeof(cmd));
    }

    void set_auto_ack(uint8_t value)
    {
        if (unlikely(!uart))
            return;

        NRF52840_UART_SYNC_W;

        uint8_t cmd[] = {CMD_CONFIG_ACK, value};
        uart->write(cmd, sizeof(cmd));
    }

    void set_auto_empty_pdu(uint8_t value)
    {
        if (unlikely(!uart))
            return;

        NRF52840_UART_SYNC_W;

        uint8_t cmd[] = {CMD_CONFIG_AUTO_EMPTY_PDU, value};
        uart->write(cmd, sizeof(cmd));
    }

    void set_log_tx(uint8_t value)
    {
        if (unlikely(!uart))
            return;

        NRF52840_UART_SYNC_W;

        uint8_t cmd[] = {CMD_CONFIG_LOG_TX, value};
        uart->write(cmd, sizeof(cmd));
    }

    void set_scan_mode()
    {
        if (unlikely(!uart))
            return;

        NRF52840_UART_SYNC_W;

        uint8_t cmd = CMD_CONFIG_SCAN_MODE;
        uart->write(&cmd, sizeof(cmd));
        uart->flushInput();
    }

    void set_bdaddress(uint8_t bdaddr[6])
    {
        if (unlikely(!uart))
            return;

        NRF52840_UART_SYNC_W;

        uint8_t cmd[7] = {CMD_CONFIG_BDADDR,
                          bdaddr[5], bdaddr[4],
                          bdaddr[3], bdaddr[2],
                          bdaddr[1], bdaddr[0]};
        uart->write(cmd, sizeof(cmd));
    }

    void set_stop_pkt_forwarding(uint8_t value)
    {
        if (unlikely(!uart))
            return;

        NRF52840_UART_SYNC_W;

        uint8_t cmd[] = {CMD_CONFIG_STOP_PKT_FORWARDING, value};
        uart->write(cmd, sizeof(cmd));
    }

    void set_channel(uint8_t value)
    {
        if (unlikely(!uart))
            return;

        NRF52840_UART_SYNC_W;

        // Send sn_nest command
        uint8_t cmd[] = {CMD_CONFIG_FORCE_CHANNEL, value};
        uart->write(cmd, sizeof(cmd));
    }

    void set_selective_jamming(uint8_t value)
    {
        if (unlikely(!uart))
            return;

        NRF52840_UART_SYNC_W;

        // Send sn_nest command
        uint8_t cmd[] = {CMD_SELECTIVE_DATA_JAMMING, value};
        uart->write(cmd, sizeof(cmd));
    }

    void set_role(uint8_t value)
    {
        this->role = value;

        // TODO: For now we just set this locally
        // if (unlikely(!uart))
        //     return;

        // NRF52840_UART_SYNC_W;

        // // Send sn_nest command
        // uint8_t cmd[] = {CMD_CONFIG_FORCE_CHANNEL, value};
        // uart->write(cmd, sizeof(cmd));
    }

    void enable_debug(bool rx_data, bool tx_data = false, bool rx_errors = false)
    {
        debug_rx_data = rx_data;
        debug_tx_data = tx_data;
        debug_rx_errors = rx_errors;
    }

    void close()
    {
        ready = false;
        if (uart) {
            uart->close();
        }
    }
};