#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>

#include <vector>
#include <map>

#include <netinet/in.h>

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

// enum to string
// https://linuxhint.com/cpp-ways-to-convert-enum-to-string/
#define enum_to_str( name ) #name
static const char* cvt_enum_to_str[] ={
	enum_to_str(IEEE80211_RADIOTAP_TSFT),
	enum_to_str(IEEE80211_RADIOTAP_FLAGS),
	enum_to_str(IEEE80211_RADIOTAP_RATE),
	enum_to_str(IEEE80211_RADIOTAP_CHANNEL),
	enum_to_str(IEEE80211_RADIOTAP_FHSS),
	enum_to_str(IEEE80211_RADIOTAP_DBM_ANTSIGNAL),
	enum_to_str(IEEE80211_RADIOTAP_DBM_ANTNOISE),
	enum_to_str(IEEE80211_RADIOTAP_LOCK_QUALITY),
	enum_to_str(IEEE80211_RADIOTAP_TX_ATTENUATION),
	enum_to_str(IEEE80211_RADIOTAP_DB_TX_ATTENUATION),
	enum_to_str(IEEE80211_RADIOTAP_DBM_TX_POWER),
	enum_to_str(IEEE80211_RADIOTAP_ANTENNA),
	enum_to_str(IEEE80211_RADIOTAP_DB_ANTSIGNAL),
	enum_to_str(IEEE80211_RADIOTAP_DB_ANTNOISE),
	enum_to_str(IEEE80211_RADIOTAP_RX_FLAGS),
	enum_to_str(IEEE80211_RADIOTAP_TX_FLAGS),
	enum_to_str(IEEE80211_RADIOTAP_RTS_RETRIES),
	enum_to_str(IEEE80211_RADIOTAP_DATA_RETRIES),
	
	enum_to_str(IEEE80211_RADIOTAP_MCS),
	enum_to_str(IEEE80211_RADIOTAP_AMPDU_STATUS),
	enum_to_str(IEEE80211_RADIOTAP_VHT),
	enum_to_str(IEEE80211_RADIOTAP_TIMESTAMP),
	
	enum_to_str(IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE),
	enum_to_str(IEEE80211_RADIOTAP_VENDOR_NAMESPACE),
	enum_to_str(IEEE80211_RADIOTAP_EXT)
};

// https://github.com/radiotap/radiotap-library/blob/master/radiotap_iter.h
typedef struct radiotap_align_size {
	uint8_t align:4, size:4;
} dot11_relem_align_size;

// https://github.com/radiotap/radiotap-library/blob/master/radiotap.c
// https://stackoverflow.com/questions/18731707/why-does-c11-not-support-designated-initializer-lists-as-c99
// C99 supports designated initializer, but C++17 does not support designated initializer.
// C++20 supports designated initializer.
static const dot11_relem_align_size dot11_relem_get_align_size[32] = {
    { .align = 8, .size = 8 },
    { .align = 1, .size = 1 },
    { .align = 1, .size = 1 },
    { .align = 2, .size = 4 },
    { .align = 2, .size = 2 },
    { .align = 1, .size = 1 },
    { .align = 1, .size = 1 },
    { .align = 2, .size = 2 },
    { .align = 2, .size = 2 },
    { .align = 2, .size = 2 }, 
    { .align = 1, .size = 1 },
    { .align = 1, .size = 1 },
    { .align = 1, .size = 1 },
    { .align = 1, .size = 1 },
    { .align = 2, .size = 2 },
    { .align = 2, .size = 2 },
    { .align = 1, .size = 1 },
    { .align = 1, .size = 1 },

    { .align = 0, .size = 0 },

    { .align = 1, .size = 3 },
    { .align = 4, .size = 8 },
    { .align = 2, .size = 12 },
    { .align = 8, .size = 12 },

    { .align = 0, .size = 0 },
    { .align = 0, .size = 0 },
    { .align = 0, .size = 0 },
    { .align = 0, .size = 0 },
    { .align = 0, .size = 0 },
    { .align = 0, .size = 0 },

    
    { .align = 0, .size = 0 },
    { .align = 0, .size = 0 },
    { .align = 0, .size = 0 }
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

typedef struct ieee80211_radiotap_elem_info {
	dot11_relem_enum type;
	uint8_t size;
	uint8_t* value;
} __attribute__((__packed__)) dot11_relem_info;

class RadiotapParser
{
private:
    uint8_t* pkt_addr;
    uint8_t hdr_ver;
    uint8_t hdr_pad;
    uint16_t hdr_len;
    uint8_t* hdr_pst_addr;
    uint32_t* presents;
    std::vector<uint32_t> rtap_present_vector;
    std::map<dot11_relem_enum, uint32_t> rtap_data_map;
public:
    RadiotapParser(uint8_t* _radiotap_header_addr);
    ~RadiotapParser();
    uint8_t get_header_version();
    uint8_t get_header_padding();
    uint16_t get_header_length();
    uint32_t get_first_present();
    std::vector<uint32_t> get_presents();
    std::map<dot11_relem_enum, uint32_t> get_radiotap_data_map();
};