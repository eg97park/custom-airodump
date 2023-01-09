#include <cstdio>
#include <cstdlib>
#include <cstdint>

typedef struct ieee80211_radiotap_header {
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present;
} __attribute__((__packed__)) dot11_radio_hdr;

struct ieee80211_beacon_frame_header {
    uint16_t		it_frame_control_field;
    uint16_t		it_duration;
    uint8_t			it_destination_address[6];
    uint8_t			it_source_address[6];
    uint8_t			it_bss_id[6];
    uint16_t		it_fragment_sequence_number;
} __attribute__((__packed__));

struct ieee80211_wireless_management_header {
	uint64_t timestamp;
	uint16_t beacon_interval;
	uint16_t capabilities_information;
} __attribute__((__packed__));

class RadiotapParser
{
private:
    void* pkt_addr;
    uint8_t hdr_ver;
    uint8_t hdr_pad;
    uint16_t hdr_len;
    void* hdr_pst_addr;
    uint32_t* presents;

public:
    RadiotapParser(void* _radiotap_header_addr);
    ~RadiotapParser();
    uint8_t get_header_version();
    uint8_t get_header_padding();
    uint16_t get_header_length();
    uint32_t get_first_present();
    uint32_t* get_presents();
};