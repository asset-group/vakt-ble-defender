#include "vaktble.hpp"

// Program Definitions
#define LINKTYPE pcpp::LinkLayerType::LINKTYPE_NORDIC_BLE
#define USB_DESC_CENTRAL "BLEDefender Central"
#define USB_DESC_PERIPHERAL "BLEDefender Peripheral"

#define CONN_SW_TIMEOUT_MULTIPLIER 40

// Macros
#define IS_LL_ADV_OPCODE(p_buffer, opcode) (((p_buffer)[9] >= 37) && (((p_buffer)[21] & 0x0F) == opcode))
#define IS_LL_ADV_IND(p_buffer) IS_LL_ADV_OPCODE(p_buffer, 0x00)
#define IS_LL_ADV_SCAN_REQ(p_buffer) IS_LL_ADV_OPCODE(p_buffer, 0x03)
#define IS_LL_ADV_SCAN_RSP(p_buffer) IS_LL_ADV_OPCODE(p_buffer, 0x04)
#define IS_LL_ADV_CONN_IND(p_buffer) IS_LL_ADV_OPCODE(p_buffer, 0x05)

#define IS_LL_OPCODE(p_buffer, opcode) (((p_buffer)[9] < 37) && (((p_buffer)[21] & 0b11) == 3) && ((p_buffer)[23] == opcode))
#define IS_LL_DATA(p_buffer) (((p_buffer)[9] < 37) && ((p_buffer)[22] > 0))
#define IS_LL_CONN_UPDATE_IND(p_buffer) IS_LL_OPCODE(p_buffer, 0x00)
#define IS_LL_CHANNEL_MAP_IND(p_buffer) IS_LL_OPCODE(p_buffer, 0x01)
#define IS_LL_TERMINATE_IND(p_buffer) IS_LL_OPCODE(p_buffer, 0x02)
#define IS_LL_FEATURE_REQ(p_buffer) IS_LL_OPCODE(p_buffer, 0x08)
#define IS_LL_FEATURE_RSP(p_buffer) IS_LL_OPCODE(p_buffer, 0x09)
#define IS_LL_CONN_PARAM_REQ(p_buffer) IS_LL_OPCODE(p_buffer, 0x0f)
#define IS_LL_CONN_PARAM_RSP(p_buffer) IS_LL_OPCODE(p_buffer, 0x10)
#define IS_LL_SLAVE_FEATURE_REQ(p_buffer) IS_LL_OPCODE(p_buffer, 0x0e)

using namespace std::chrono;

enum BLE_CONNECTION_STATE {
    CONN_STATE_ADV = 0x00, // Listening on adv. channels
    CONN_STATE_INITIATING, // Anchor point is to be received/sent
    CONN_STATE_DATA        // Anchor point has been sent or reponded to
};

typedef struct _ble_scan_name_t {
    uint8_t scan_valid;
    string device_name;
    wd_field_t device_name_field;
    uint8_t device_bdaddr[6];
    wd_field_t device_bdaddr_field;

    void init(string target_name)
    {
        device_name = target_name;
        device_name_field = wd_field("btcommon.eir_ad.entry.device_name");
        device_bdaddr_field = wd_field("btle.advertising_address");
        if (!device_name_field || !device_bdaddr_field)
            GL1R("ble_scan_name_t: Error. wdissector might not have been initialized");
    }

    void register_scan(wd_t *wd)
    {
        wd_register_field(wd, device_name_field);
        wd_register_field(wd, device_bdaddr_field);
    }

    bool read_scan(wd_t *wd)
    {
        // Read field of received device name
        wd_field_info_t fi_name = wd_read_field(wd, device_name_field);
        if (!fi_name)
            return false;

        // Read field of received adv. bdaddr
        wd_field_info_t fi_addr = wd_read_field(wd, device_bdaddr_field);
        if (!fi_addr)
            return false;

        // Extract received device name string
        const char *recv_name = packet_read_field_string(fi_name);
        if (!recv_name)
            return false;

        if (!scan_valid)
            GL1C("Scanning: RX <-- ADV \"{}\"", recv_name);

        // Check if name of BLE peripheral matches the target name
        if (strcmp(recv_name, device_name.c_str()))
            return false;

        // name matches, now extract bdaddress string
        const char *bd_addr = packet_read_field_string(fi_addr);
        if (!bd_addr)
            return false;

        // extract bdaddr array (6 bytes)
        GByteArray *bd_addr_val = packet_read_field_bytes(fi_addr);
        if (bd_addr_val->len < 6)
            return false;

        // Save bdaddress of the target device in device_bdaddr
        memcpy(device_bdaddr, bd_addr_val->data, 6);

        GL1G("[!] Device Found! BDAddress: \"{}\"", bd_addr);

        scan_valid = 1;
        return true;
    }
} ble_scan_name_t;

typedef struct _ble_filter_t {
    wd_filter_t filter;

    bool init(const char *filter_string)
    {
        if (filter = wd_filter(filter_string))
            return true;
        return false;
    }

    void register_filter(wd_t *wd)
    {
        wd_register_filter(wd, filter);
    }

    bool read_filter(wd_t *wd)
    {
        return wd_read_filter(wd, filter);
    }
} ble_filter_t;

// Framework Instances
argparse::ArgumentParser program("vaktble");
PacketLogger LoggerPeripheral;
PacketLogger LoggerCentral;
nRF52840Driver DriverPeripheral;
nRF52840Driver DriverCentral;
WDPacketHandler<driver_nrf52840_event_t> PacketHandler;
WDEventQueue<driver_nrf52840_event_t> EventsQueue;
WDSignalHandler SignalHandler;
WDGlobalTimeout GlobalTimeout;

// Global variables
wd_t *wd = nullptr; // Global wdissector instance
ble_scan_name_t ble_scan_name = {0};
ble_filter_t filter_user = {0};
uint8_t state_periph = CONN_STATE_ADV;
uint8_t state_central = CONN_STATE_ADV;
vector<uint8_t> saved_conn_ind;
uint8_t conn_periph_window_size;
uint16_t conn_periph_window_offset;
uint16_t conn_periph_interval;
uint16_t conn_periph_timeout;
uint8_t conn_periph_hop;
folly::USPSCQueue<vector<uint8_t>, false, 8> queue_to_real_central;
folly::USPSCQueue<vector<uint8_t>, false, 8> queue_to_real_peripheral;
vector<uint8_t> pkt_ll_unknown_rsp = {0x01, 0x00, 0x00, 0x00, 0x03, 0x02, 0x07, 0x00, 0xe8, 0x8d, 0xe4};
vector<uint8_t> pkt_ll_reject_ind = {0x01, 0x00, 0x00, 0x00, 0x03, 0x02, 0x0d, 0x0c, 0x27, 0x96, 0x35};

int opt_channel = 39;
bool opt_passthrough = false;
bool opt_log_pkt_peripheral = false;
bool opt_log_pkt_central = false;
bool opt_log_pkt_peripheral_data = false;
bool opt_log_pkt_central_data = false;
bool opt_no_rt_sched = false;
bool opt_log_show_empty_pdus = false;
bool opt_selective_jamming = false;
bool opt_validate = false;

// Function Prototypes
void TerminateConnection(const char *reason_string, uint8_t role);
void ForwardPacket(driver_nrf52840_event_t &pkt);

// Main code functions
void ConfigurePacketHandler(WDPacketHandler<driver_nrf52840_event_t> &PacketHandler, function<void(driver_nrf52840_event_t &)> fcn)
{
    PacketHandler.SetPacketEventsHandler(fcn, !opt_no_rt_sched, []() {
        if (wd)
            return;
        wd = wd_init("proto:nordic_ble");
        if (!wd) {
            GL1R("protocol cannot initialize!");
            exit(1);
        }

        GL1M("{}", wdissector_version_info());

        wd_set_dissection_mode(wd, WD_MODE_FAST);
    });
}

void HandleNRF52Driver(WDEventQueue<driver_nrf52840_event_t> &PacketQueue, nRF52840Driver &Driver)
{
    while (true) {
        driver_nrf52840_event_t pkt_evt = Driver.receive();
        if (unlikely(!pkt_evt.evt || (pkt_evt.evt && !pkt_evt.data_size)))
            continue;

        // TODO: handle serial port auto reconnection

        PacketQueue.PushEvent(pkt_evt);
    }
}

static inline void HandleStates(driver_nrf52840_event_t &pkt)
{
    uint8_t *raw_pkt = pkt.data.data();

    // Handle peripheral states (Master interface)
    if (pkt.role == ROLE_PERIPHERAL)
        switch (state_periph) {
        case CONN_STATE_ADV:
            if (pkt.evt == CMD_DATA_RX && IS_LL_ADV_CONN_IND(raw_pkt)) {
                if (pkt.data_size < 22) {
                    GL1R("Invalid CONN_IND received, len:{} < 22", pkt.data_size);
                    return;
                }

                state_periph = CONN_STATE_INITIATING;
                saved_conn_ind = vector<uint8_t>(&raw_pkt[pkt.data_offset], &raw_pkt[pkt.data_offset] + pkt.data_size);
                // Change some parameters to avoid collisions
                saved_conn_ind[18] = 0xCC;     // Access Address
                saved_conn_ind[22] = 0xAA;     // CRCInit
                saved_conn_ind[39] = 0x20 | 7; // Hop Interval

                conn_periph_window_size = raw_pkt[42];
                conn_periph_window_offset = *((uint16_t *)&raw_pkt[43]);
                conn_periph_interval = *((uint16_t *)&raw_pkt[45]);
                conn_periph_timeout = *((uint16_t *)&raw_pkt[49]);
                conn_periph_hop = raw_pkt[56] & 0b11111;

                GL1G("[1/4] Periph: Recv. Connection Indication from Central");
                GL1G("      Window:{}+{}, Interval:{}, Timeout:{}, Hop:{}",
                     conn_periph_window_offset,
                     conn_periph_window_size,
                     conn_periph_interval,
                     conn_periph_timeout,
                     conn_periph_hop);
                // Start timeout for CONN_STATE_INITIATING
                uint64_t timeout_ms = (uint64_t)((double)(conn_periph_window_offset + conn_periph_window_size + conn_periph_interval + 1) * 1.25);
                GlobalTimeout.init(timeout_ms, true, [](WDGlobalTimeout &gt, void *ptr) {
                    TerminateConnection("Connection Init Timeout", ROLE_PERIPHERAL);
                    return false;
                });
            }
            break;
        case CONN_STATE_INITIATING:
            if (pkt.channel < 37) {
                GlobalTimeout.StopTimeout();

                static bool got_anchor = false;
                if (!got_anchor) {
                    got_anchor = true;
                    GL1G("[2/4] Periph: Got Anchor Point " COLOR_YELLOW "{}", pkt.pkt_summary);
                }
                // Wait at least 5 empty pdus/data
                // static int data_recv = 0;
                // if (data_recv++ < 5)
                //     break;
                // data_recv = 0;

                got_anchor = false;
                state_periph = CONN_STATE_DATA;
                // Send connection request to real peripheral
                // after connection with the central is established
                DriverCentral.send(saved_conn_ind);

                // Start timeout for CONN_STATE_INITIATING
                uint64_t timeout_ms = conn_periph_interval * CONN_SW_TIMEOUT_MULTIPLIER;
                if (timeout_ms > conn_periph_timeout * 10) // Limit timeout to supervision timeout
                    timeout_ms = conn_periph_timeout * 10;

                GlobalTimeout.init(timeout_ms, true, [&](WDGlobalTimeout &gt, void *ptr) {
                    got_anchor = false;
                    TerminateConnection("RX Timeout", ROLE_PERIPHERAL);
                    return false;
                });
            }
            break;
        case CONN_STATE_DATA:

            if (pkt.evt == CMD_DATA_RX)
                GlobalTimeout.RestartTimeout(); // Reset software timer when receiving RX

            if (IS_LL_TERMINATE_IND(pkt.data.data())) {
                GlobalTimeout.StopTimeout();
                TerminateConnection("Recv. LL_TERMINATE_IND", pkt.role);
                state_periph = CONN_STATE_ADV;
            }
            else if (pkt.channel >= 37) {
                GlobalTimeout.StopTimeout();
                TerminateConnection("Supervision Timeout", pkt.role);
                state_periph = CONN_STATE_ADV;
            }
            break;
        }
    // Handle central states (Slave interface)
    else if (pkt.role == ROLE_CENTRAL)
        switch (state_central) {
        case CONN_STATE_ADV:
            if (pkt.evt == CMD_DATA_TX && IS_LL_ADV_CONN_IND(pkt.data.data())) {
                GL1G("[3/4] Central: Connecting to legitimate peripheral...");
                state_central = CONN_STATE_INITIATING;
            }
            break;
        case CONN_STATE_INITIATING:
            if (pkt.channel < 37) {
                GL1G("[4/4] Central: Got anchor point response from legitimate periph.");
                state_central = CONN_STATE_DATA;
            }
            break;
        case CONN_STATE_DATA:
            if (IS_LL_TERMINATE_IND(pkt.data.data())) {
                GlobalTimeout.StopTimeout();
                TerminateConnection("Recv. LL_TERMINATE_IND", pkt.role);
                state_central = CONN_STATE_ADV;
            }
            break;
        }
}

void HandlePacket(driver_nrf52840_event_t &pkt)
{
    if (opt_validate)
        filter_user.register_filter(wd);

    // Fast check for common conditions
    wd_set_packet_direction(wd, pkt.evt == (CMD_DATA_TX ? WD_DIR_TX : WD_DIR_RX));
    wd_packet_dissect(wd, &pkt.data[0], pkt.data.size());

    if (opt_validate)
        pkt.pkt_valid = filter_user.read_filter(wd);
    else
        pkt.pkt_valid = true;

    if (pkt.pkt_valid)
        ForwardPacket(pkt);

    // Update user event variables
    pkt.pkt_summary = wd_packet_summary(wd);

PACKET_END:
    pkt.pkt_save = true;

    clock_gettime(CLOCK_MONOTONIC, &pkt.timestamp_user);

    EventsQueue.PushEvent(pkt);
}

void HandlePacketScanning(driver_nrf52840_event_t &pkt)
{
    // handle scanning advertisements packets
    ble_scan_name.register_scan(wd);

    wd_set_packet_direction(wd, pkt.evt == (CMD_DATA_TX ? WD_DIR_TX : WD_DIR_RX));
    wd_packet_dissect(wd, &pkt.data[0], pkt.data.size());

    if (ble_scan_name.read_scan(wd)) {
        // Address found, now switch to normal packet handler
        ConfigurePacketHandler(PacketHandler, HandlePacket);
        DriverPeripheral.set_bdaddress(ble_scan_name.device_bdaddr);
        DriverCentral.set_bdaddress(ble_scan_name.device_bdaddr);
    }

    // Update user event variables
    pkt.pkt_summary = wd_packet_summary(wd);
    pkt.pkt_valid = true; // Assume all adv packets are ok for now (TODO: conn_ind validation)
    pkt.pkt_save = true;

    clock_gettime(CLOCK_MONOTONIC, &pkt.timestamp_user);

    EventsQueue.PushEvent(pkt);
}

void HandleEvents(driver_nrf52840_event_t &pkt)
{
    if (unlikely(!pkt.pkt_valid || ((opt_log_pkt_central || (opt_log_pkt_central_data && pkt.channel < 37)) && pkt.role == ROLE_CENTRAL) ||
                 ((opt_log_pkt_peripheral || (opt_log_pkt_peripheral_data && pkt.channel < 37)) && pkt.role == ROLE_PERIPHERAL))) {
        if (opt_log_show_empty_pdus || IS_LL_DATA(pkt.data.data())) {
            fmt::print("[{:04}] {}({}) {}" COLOR_RESET
                       " Ch:" COLOR_YELLOW "{:02}" COLOR_RESET
                       ", Evt:" COLOR_YELLOW "{:03}" COLOR_RESET
                       ", ΔT:" COLOR_YELLOW "{:03}" COLOR_RESET "us"
                       ", S:{}" COLOR_RESET
                       ", " COLOR_YELLOW "{}" COLOR_RESET "\n",
                       pkt.pkt_counter,
                       (pkt.role == ROLE_CENTRAL ? COLOR_GREEN : COLOR_RED),
                       (pkt.role == ROLE_CENTRAL ? "C" : "P"),
                       (pkt.evt == CMD_DATA_TX ? COLOR_CYAN "TX -->" : COLOR_GREEN "RX <--"),
                       pkt.channel,
                       pkt.event_counter,
                       DIFF_TIMESPEC_US(pkt.timestamp_software, pkt.timestamp_user),
                       (pkt.pkt_valid ? COLOR_GREEN "✔️" : COLOR_RED "✖️"),
                       pkt.pkt_summary);
            if (unlikely(!pkt.pkt_valid))
                GL1R("[!] Packet above won't be forwarded to peripheral!");
        }
    }

    HandleStates(pkt);

    if (pkt.pkt_save) {
        if (pkt.role == ROLE_CENTRAL)
            LoggerCentral.write(pkt.data);
        else
            LoggerPeripheral.write(pkt.data);
    }
}

void ForwardPacket(driver_nrf52840_event_t &pkt)
{

    uint8_t *raw_pkt = pkt.data.data();

    if (!IS_LL_DATA(raw_pkt) || (pkt.evt != CMD_DATA_RX)) // Ignore empty PDUs or TXs
        goto FORWARD_END;

    // Ignore certain control packets
    if ((!IS_LL_CONN_UPDATE_IND(raw_pkt)) &&
        (!IS_LL_CHANNEL_MAP_IND(raw_pkt)) &&
        (!IS_LL_CONN_PARAM_REQ(raw_pkt)) &&
        (!IS_LL_CONN_PARAM_RSP(raw_pkt)) &&
        (!IS_LL_SLAVE_FEATURE_REQ(raw_pkt))) {

        // Downgrade features capabilities (only allow encryption)
        if (IS_LL_SLAVE_FEATURE_REQ(raw_pkt) ||
            IS_LL_FEATURE_RSP(raw_pkt) ||
            IS_LL_FEATURE_REQ(raw_pkt)) {
            memset(&pkt.data[24], 0, 8);
            pkt.data[24] = 0x01;
        }

        // Store packets to be forwarded
        // vector<uint8_t> pkt_to_queue(&pkt.data[pkt.data_offset], &pkt.data[pkt.data_offset] + pkt.data_size);
        if (pkt.role == ROLE_PERIPHERAL)
            queue_to_real_central.enqueue({&pkt.data[pkt.data_offset], &pkt.data[pkt.data_offset] + pkt.data_size});
        else if (pkt.role == ROLE_CENTRAL)
            queue_to_real_peripheral.enqueue({&pkt.data[pkt.data_offset], &pkt.data[pkt.data_offset] + pkt.data_size});
    }

FORWARD_END:
    // ----------- Evaluate queues -----------
    static vector<uint8_t> pkt_tx;
    // Forward packets to target peripheral
    if (state_central == CONN_STATE_DATA)
        while (queue_to_real_central.try_dequeue(pkt_tx))
            DriverCentral.send(pkt_tx);

    // Forward packets to untrusted central
    if (state_periph == CONN_STATE_DATA)
        while (queue_to_real_peripheral.try_dequeue(pkt_tx))
            DriverPeripheral.send(pkt_tx);
}

void TerminateConnection(const char *reason_string, uint8_t role)
{
    // Cleanup Queues
    vector<uint8_t> dummy;
    while (queue_to_real_peripheral.try_dequeue(dummy))
        ;
    while (queue_to_real_central.try_dequeue(dummy))
        ;

    // Command driver to go back to advertisement channels
    DriverPeripheral.set_channel(opt_channel);
    DriverCentral.set_channel(opt_channel);
    // Reset state of vaktble periph and central
    state_periph = CONN_STATE_ADV;
    state_central = CONN_STATE_ADV;

    if (program.is_used("-n")) {
        // Configure scanning handler if bdaddress is not known
        ConfigurePacketHandler(PacketHandler, HandlePacketScanning);
    }

    GL1Y("===============================================================================");
    GL1Y("Disconnection Detected! Resetting bridge.\nReason: " COLOR_CYAN "{}\n" COLOR_YELLOW "Role: " COLOR_CYAN "{}",
         reason_string,
         (role == ROLE_CENTRAL ? "Central" : "Peripheral"));
    GL1G("Going back to scanning target...");
    GL1Y("===============================================================================");
}

int main(int argc, char const *argv[])
{
    program.add_description("A BLE bridge to defend a peripheral against malicious connections");
    program.add_argument("-v", "--validation").default_value(false).implicit_value(true).help("Enable LL Validation");
    program.add_argument("-p", "--bridge-port-p").default_value("/dev/ttyACM0").help("Serial port of Peripheral Impersonator");
    program.add_argument("-c", "--bridge-port-c").default_value("/dev/ttyACM1").help("Serial port of Central Impersonator");
    program.add_argument("-a", "--address").default_value("aa:bb:cc:dd:ee").help("BDAddress of Peripheral to defend");
    program.add_argument("-n", "--name").default_value("nimble-bleprph").help("Name of Peripheral to defend");
    program.add_argument("-s", "--selective-jamming").default_value(false).implicit_value(true).help("Enable Selective Jamming (ATT RSP)");
    program.add_argument("--channel").default_value(39).scan<'i', int>().help("Forcebly select the BLE channel");
    program.add_argument("--passthrough").default_value(false).implicit_value(true).help("Enable passthrough mode (validation disabled)");
    program.add_argument("--no-rt-sched").default_value(false).implicit_value(true).help("Don't use realtime scheduler (RR)");
    program.add_argument("--no-gpio-en").default_value(false).implicit_value(true).help("Disable automatic radio power off/on control");
    program.add_argument("--gpio-en-peripheral").default_value(9).scan<'i', int>().help("gpio to enable/disable peripheral radio (arm64 only)");
    program.add_argument("--gpio-en-central").default_value(10).scan<'i', int>().help("gpio to enable/disable central radio (arm64 only)");
    program.add_argument("--debug-rx").default_value(false).implicit_value(true).help("Show raw RX packets");
    program.add_argument("--debug-tx").default_value(false).implicit_value(true).help("Show raw TX packets");
    program.add_argument("--debug-rx-errors").default_value(false).implicit_value(true).help("Show RX reception errors");
    program.add_argument("--debug-pkt-peripheral").default_value(false).implicit_value(true).help("Print decoded packets for peripheral");
    program.add_argument("--debug-pkt-central").default_value(false).implicit_value(true).help("Print decoded packets for central");
    program.add_argument("--debug-pkt-peripheral-data").default_value(false).implicit_value(true).help("Print decoded packets for peripheral data");
    program.add_argument("--debug-pkt-central-data").default_value(false).implicit_value(true).help("Print decoded packets for central data");
    program.add_argument("--debug-pkt-show-empty-pdus").default_value(false).implicit_value(true).help("Show empty PDUs in decoded packets");
    program.parse_args(argc, argv);

    // Check root
    if (getuid()) {
        GL1R("Error: Not running as root.");
        exit(1);
    }

    // Print banner
    system("./scripts/banner.ansi");

    // Update global config vars
    opt_validate = program.get<bool>("--validation");
    opt_channel = program.get<int>("--channel");
    opt_selective_jamming = program.get<bool>("--selective-jamming");
    opt_no_rt_sched = program.get<bool>("--no-rt-sched");
    opt_log_pkt_central = program.get<bool>("--debug-pkt-central");
    opt_log_pkt_peripheral = program.get<bool>("--debug-pkt-peripheral");
    opt_log_pkt_peripheral_data = program.get<bool>("--debug-pkt-peripheral-data");
    opt_log_pkt_central_data = program.get<bool>("--debug-pkt-central-data");
    opt_log_show_empty_pdus = program.get<bool>("--debug-pkt-show-empty-pdus");

    DriverPeripheral.enable_debug(program.get<bool>("--debug-rx"),
                                  program.get<bool>("--debug-tx"),
                                  program.get<bool>("--debug-rx-errors"));

    DriverCentral.enable_debug(program.get<bool>("--debug-rx"),
                               program.get<bool>("--debug-tx"),
                               program.get<bool>("--debug-rx-errors"));

    if (!DriverPeripheral.init((program.is_used("-p") ? program.get<string>("-p") : USB_DESC_PERIPHERAL),
                               115200, 20, false, true)) {
        GL1R("{}Error initializing nRF52840 Driver. Check serial port!", DriverPeripheral.TAG);
        exit(1);
    }

    if (!DriverCentral.init((program.is_used("-c") ? program.get<string>("-c") : USB_DESC_CENTRAL),
                            115200, 20, false, true)) {
        GL1R("{}Error initializing nRF52840 Driver. Check serial port!", DriverCentral.TAG);
        exit(1);
    }

    DriverPeripheral.set_role(ROLE_PERIPHERAL);
    DriverCentral.set_role(ROLE_CENTRAL);
    DriverPeripheral.set_channel(opt_channel);
    DriverCentral.set_channel(opt_channel);
    DriverPeripheral.set_log_tx(true);
    DriverCentral.set_log_tx(true);
    DriverCentral.set_jamm_conn_ind(1);
    DriverCentral.set_selective_jamming(opt_selective_jamming);
    // DriverPeripheral.set_auto_disconnect(1); // TODO: fix timer of peripheral and central

    EnsureFolder("logs");
    if (!LoggerPeripheral.init("logs/capture_ble_peripheral.pcapng", LINKTYPE, false, false)) {
        GL1R("Peripheral Logger could not start");
        exit(1);
    }
    if (!LoggerCentral.init("logs/capture_ble_central.pcapng", LINKTYPE, false, false)) {
        GL1R("Central Logger could not start");
        exit(1);
    }

    // Configure Packet Handler
    PacketHandler.AddSimplePacketHandlerWithDriver<nRF52840Driver>(DriverPeripheral,
                                                                   HandleNRF52Driver,
                                                                   !opt_no_rt_sched,
                                                                   "drv_peripheral");

    PacketHandler.AddSimplePacketHandlerWithDriver<nRF52840Driver>(DriverCentral,
                                                                   HandleNRF52Driver,
                                                                   !opt_no_rt_sched,
                                                                   "drv_central");

    if (program.is_used("-n")) {
        // Configure scanning handler (bdaddress is not known)
        ConfigurePacketHandler(PacketHandler, HandlePacketScanning);
    }
    else // Configure Default handler (bdaddress is known)
    {
        // DriverPeripheral.set_bdaddress(ble_scan_name.device_bdaddr);
        ConfigurePacketHandler(PacketHandler, HandlePacket);
    }

    // Configure Events handler
    EventsQueue.SetEventHandler(HandleEvents);

    // Initialize common filters
    ble_scan_name.init(program.get<string>("-n"));
    filter_user.init("!(btatt.opcode.method == 0x0a && btatt.uuid16 == 0x2a00)");

    // Configure and install signal handler
    SignalHandler.CallStop(PacketHandler);
    SignalHandler.CallStop(LoggerPeripheral);
    SignalHandler.CallStop(LoggerCentral);
    SignalHandler.init();

    // Run PacketHandler and wait
    PacketHandler.Run();

    return 0;
}
