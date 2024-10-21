
extern "C" {
#define USE_US_TIMER 1
#include <user_interface.h>
}
#define DISABLE 0
#define ENABLE  1

#define OFFSET_80211 12
#define TYPE_MANAGEMENT       0x00
#define TYPE_CONTROL          0x01
#define TYPE_DATA             0x02
#define SUBTYPE_PROBE_REQUEST 0x04



uint8_t packet_probe_reponse[] = { 0x50, 0x00, //Frame Control
                                   0x3a, 0x01, //Duration 314us
                                   /*4*/   0x28, 0xc6, 0x3f, 0xa8, 0xaf, 0xc5, //Destination address
                                   /*10*/  0x28, 0xc6, 0x3f, 0xa8, 0xaf, 0xc5, //Source address - overwritten later
                                   /*16*/  0x28, 0xc6, 0x3f, 0xa8, 0xaf, 0xc5, //BSSID - overwritten to the same as the source address
                                   /*22*/  0x00, 0x00, //Seq-ctl
                                   //Frame body starts here
                                   /*24*/  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //timestamp - the number of microseconds the AP has been active
                                   /*32*/  0x64, 0x00, //Beacon interval
                                   /*34*/  0x11, 0x00, //Capability info

                                   /* Tag parameters */
                                   0x00, 0x08, 'T', 'E', 'S', 'T', '_', 'K', 'R', 'A', /* SSID */
                                   0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24, /* Rates */
                                   0x03, 0x01, 0x09,  /* Current Channel */
                                   0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x01, 0x00, 0x00,
                                 };


uint8_t packet_ack[] = { 0xd4, 0x00, //Frame Control
                         0x3a, 0x01, //Duration
                         /*4*/   0xa4, 0x50, 0x46, 0x59, 0x0c, 0x91, //Destination address ---- insert,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 //padding.

                       };


typedef struct {
  signed rssi: 8; // signal intensity of packet
  unsigned rate: 4;
  unsigned is_group: 1;
  unsigned: 1;
  unsigned sig_mode: 2; // 0:is 11n packet; 1:is not 11n packet;
  unsigned legacy_length: 12; // if not 11n packet, shows length of packet.
  unsigned damatch0: 1;
  unsigned damatch1: 1;
  unsigned bssidmatch0: 1;
  unsigned bssidmatch1: 1;
  unsigned MCS: 7; // if is 11n packet, shows the modulation and code used (range from 0 to 76)
  unsigned CWB: 1; // if is 11n packet, shows if is HT40 packet or not
  unsigned HT_length: 16; // if is 11n packet, shows length of packet.
  unsigned Smoothing: 1;
  unsigned Not_Sounding: 1;
  unsigned: 1;
  unsigned Aggregation: 1;
  unsigned STBC: 2;
  unsigned FEC_CODING: 1; // if is 11n packet, shows if is LDPC packet or not.
  unsigned SGI: 1;
  unsigned rxend_state: 8;
  unsigned ampdu_cnt: 8;
  unsigned channel: 4; //which channel this packet in.
  unsigned: 12;
} RadioTap;

typedef struct {
  unsigned version: 2;
  unsigned frameType: 2;
  unsigned frameSubType: 4;

  unsigned toDS: 1;
  unsigned fromDS: 1;
  unsigned moreFragments: 1;
  unsigned retry: 1;
  unsigned powerManagement: 1;
  unsigned moreData: 1;
  unsigned isProtected: 1;
  unsigned order: 1;

  unsigned duration: 15;
  unsigned contentioFree: 1;

  uint8_t receiver[6];
  uint8_t source[6];
  uint8_t transmiter[6];
} Header80211;


uint8_t fake_ap_mac[6] = {0x28, 0xc6, 0x3f, 0xa8, 0xaf, 0xc5};
uint8_t broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static inline uint8_t ICACHE_FLASH_ATTR mac_cmp(uint8_t *buffer1, uint8_t *buffer2, uint8_t bytes) {
  for (uint8_t i = 0; i < bytes; i++)
  {
    if (buffer1[i] != buffer2[i]) return 0;
  }
  return 1;
}

static inline void ICACHE_FLASH_ATTR getMAC(uint8_t* data, uint16_t offset) {
  printf("%02x:%02x:%02x:%02x:%02x:%02x\n", data[offset + 0], data[offset + 1], data[offset + 2], data[offset + 3], data[offset + 4], data[offset + 5]);
}

/**
   Callback for promiscuous mode
*/
static void ICACHE_FLASH_ATTR sniffer_callback(uint8_t *buffer_pkt, uint16_t length) {
  buffer_pkt += OFFSET_80211;

  //if(buffer[0]==0xd4) return;
  Header80211 *pkt = (Header80211*) buffer_pkt;
  //printf("Type:%d SubType:%d\n",(uint8_t)pkt->frameType,(uint8_t)pkt->frameSubType);

  if (buffer_pkt[0] == 0xD4 || buffer_pkt[0] == 0xC4) return; // Do not respond Control frames

  if (mac_cmp(fake_ap_mac, pkt->receiver, 6)) { // unicast

    packet_ack[4] = pkt->source[0];
    packet_ack[5] = pkt->source[1];
    packet_ack[6] = pkt->source[2];
    packet_ack[7] = pkt->source[3];
    packet_ack[8] = pkt->source[4];
    packet_ack[9] = pkt->source[5];
    wifi_send_pkt_freedom(packet_ack, sizeof(packet_ack), 0); // send ack

    if (buffer_pkt[0] == 0x40) { // Probe request
      packet_probe_reponse[4] = pkt->source[0];
      packet_probe_reponse[5] = pkt->source[1];
      packet_probe_reponse[6] = pkt->source[2];
      packet_probe_reponse[7] = pkt->source[3];
      packet_probe_reponse[8] = pkt->source[4];
      packet_probe_reponse[9] = pkt->source[5];
      wifi_send_pkt_freedom(packet_probe_reponse, sizeof(packet_probe_reponse), 0); // probe response
      return;
    }
  }
  else if (mac_cmp(broadcast_mac, pkt->receiver, 6)) // broadcast
  {
    if (length > 82 + OFFSET_80211) { // we need to have at least 82 bytes (+ RadioTap size) to get to the ssid tag size
      if (buffer_pkt[0] == 0x40) { // Probe request wildcard

        //packet_probe_reponse[4] = pkt->source[0];
        //packet_probe_reponse[5] = pkt->source[1];
        //packet_probe_reponse[6] = pkt->source[2];
        //packet_probe_reponse[7] = pkt->source[3];
        //packet_probe_reponse[8] = pkt->source[4];
        //packet_probe_reponse[9] = pkt->source[5];

        wifi_send_pkt_freedom(packet_probe_reponse, sizeof(packet_probe_reponse), 0); // probe response
        //Seril.println(buffer_pkt[81], HEX);
      }
    }
  }
}







void setup() {
  // set the WiFi chip to "promiscuous" mode aka monitor mode
  //system_update_cpu_freq(SYS_CPU_160MHZ);
  Serial.begin(115200);
  wifi_set_macaddr(STATION_IF, fake_ap_mac);
  delay(10);
  wifi_set_opmode(STATION_MODE);
  wifi_set_channel(9);
  wifi_promiscuous_enable(DISABLE);
  delay(10);
  wifi_set_promiscuous_rx_cb(sniffer_callback);
  delay(10);
  wifi_promiscuous_enable(ENABLE);

  //ESP.wdtDisable();
  //ESP.wdtEnable(WDTO_8S);

}

void loop() {

}
