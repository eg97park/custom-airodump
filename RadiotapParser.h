#include <cstdio>
#include <cstdlib>
#include <cstdint>

#include <vector>
#include <map>

#pragma pack(1)

// https://github.com/radiotap/radiotap-library/blob/master/radiotap.h
typedef enum ieee80211_radiotap_presence {
	IEEE80211_RADIOTAP_TSFT = 0,
	IEEE80211_RADIOTAP_FLAGS = 1,
	IEEE80211_RADIOTAP_RATE = 2,
	IEEE80211_RADIOTAP_CHANNEL = 3,
	IEEE80211_RADIOTAP_FHSS = 4,
	IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5,
	IEEE80211_RADIOTAP_DBM_ANTNOISE = 6,
	IEEE80211_RADIOTAP_LOCK_QUALITY = 7,
	IEEE80211_RADIOTAP_TX_ATTENUATION = 8,
	IEEE80211_RADIOTAP_DB_TX_ATTENUATION = 9,
	IEEE80211_RADIOTAP_DBM_TX_POWER = 10,
	IEEE80211_RADIOTAP_ANTENNA = 11,
	IEEE80211_RADIOTAP_DB_ANTSIGNAL = 12,
	IEEE80211_RADIOTAP_DB_ANTNOISE = 13,
	IEEE80211_RADIOTAP_RX_FLAGS = 14,
	IEEE80211_RADIOTAP_TX_FLAGS = 15,
	IEEE80211_RADIOTAP_RTS_RETRIES = 16,
	IEEE80211_RADIOTAP_DATA_RETRIES = 17,
	
	/* 18 is XChannel, but it's not defined yet */
	IEEE80211_RADIOTAP_MCS = 19,
	IEEE80211_RADIOTAP_AMPDU_STATUS = 20,
	IEEE80211_RADIOTAP_VHT = 21,
	IEEE80211_RADIOTAP_TIMESTAMP = 22,

	/* valid in every it_present bitmap, even vendor namespaces */
	IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE = 29,
	IEEE80211_RADIOTAP_VENDOR_NAMESPACE = 30,
	IEEE80211_RADIOTAP_EXT = 31
} dot11_relem_enum;

static const size_t dot11_relem_sz[32] = {
    8, 1, 1, 4, 2, 1, 1, 2, 2, 2, 1, 1, 1, 1, 2, 2, 1, 1,
    NULL,
    3, 8, 12, 12,
    NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL
};

typedef struct ieee80211_radiotap_header {
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present;
} __attribute__((__packed__)) dot11_rhdr;

typedef struct ieee80211_beacon_frame_header {
    uint16_t		it_frame_control_field;
    uint16_t		it_duration;
    uint8_t			it_destination_address[6];
    uint8_t			it_source_address[6];
    uint8_t			it_bss_id[6];
    uint16_t		it_fragment_sequence_number;
} __attribute__((__packed__)) dot11_bhdr;

typedef struct ieee80211_wireless_management_header {
	uint64_t timestamp;
	uint16_t beacon_interval;
	uint16_t capabilities_information;
} __attribute__((__packed__)) dot11_whdr;

class RadiotapParser
{
private:
    void* pkt_addr;
    uint8_t hdr_ver;
    uint8_t hdr_pad;
    uint16_t hdr_len;
    void* hdr_pst_addr;
    uint32_t* presents;
    std::map<dot11_relem_enum, uint64_t> rtap_data_map;
public:
    RadiotapParser(void* _radiotap_header_addr);
    ~RadiotapParser();
    uint8_t get_header_version();
    uint8_t get_header_padding();
    uint16_t get_header_length();
    uint32_t get_first_present();
    std::vector<uint32_t> get_presents();
    std::map<dot11_relem_enum, uint64_t> get_radiotap_data_map();
};