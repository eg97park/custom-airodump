#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>

#include <vector>
#include <map>

#include <netinet/in.h>


const uint16_t TYPE_BEACON_FRAME = 0x80;
const uint16_t TYPE_DATA_FRAME = 0x08;

const size_t MAX_SSID_LENGTH = 32;

const size_t DOT11_WLANM_FIXED_PARAM_SIZE = 12;
const size_t DOT11_WLANM_TAG_NUMBER_SIZE = 1;
const size_t DOT11_WLANM_TAG_LENGTH_SIZE = 1;


#pragma pack(1)


/**
 * @brief radiotap present bit 파싱용 enum.
 * 
 * @ref https://github.com/radiotap/radiotap-library/blob/master/radiotap.h
 */
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


/**
 * @brief radiotap present bit enum 값을 radiotap data field 이름으로 바꿔주는 매크로.
 * 
 * @ref https://linuxhint.com/cpp-ways-to-convert-enum-to-string/
 */
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

    "NOT_IMPLEMENTED_PLUS_CHANNEL",
    
    enum_to_str(IEEE80211_RADIOTAP_MCS),
    enum_to_str(IEEE80211_RADIOTAP_AMPDU_STATUS),
    enum_to_str(IEEE80211_RADIOTAP_VHT),
    enum_to_str(IEEE80211_RADIOTAP_TIMESTAMP),

    "NOT_IMPLEMENTED_HE_INFORMATION",
    "NOT_IMPLEMENTED_HE__MU_INFORMATION",
    "NOT_IMPLEMENTED_NULL", // 이거 뭐임?
    "NOT_IMPLEMENTED_0_LENGTH_PSDU",
    "NOT_IMPLEMENTED_L_SIG",
    "NOT_IMPLEMENTED_TLVS",
    
    enum_to_str(IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE),
    enum_to_str(IEEE80211_RADIOTAP_VENDOR_NAMESPACE),
    enum_to_str(IEEE80211_RADIOTAP_EXT)
};


/**
 * @brief radiotap data field의 각 속성별 할당 값과 크기를 저장할 구조체.
 * 
 * @ref https://github.com/radiotap/radiotap-library/blob/master/radiotap_iter.h
 */
typedef struct radiotap_align_size {
    uint8_t align:4, size:4;
} __attribute__((__packed__)) dot11_relem_align_size;


/**
 * @brief radiotap data field의 각 속성별 할당 값과 크기 가져오기용 배열. padding 계산용.
 * 
 * @ref https://github.com/radiotap/radiotap-library/blob/master/radiotap.c
 * @attention designated initializer은 C99에만 지원되고, C++17은 지원 안됨. C++20부터 지원.
 */
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


/**
 * @brief radiotap header 구조체.
 * 
 * @ref https://www.radiotap.org/
 */
typedef struct ieee80211_radiotap_header {
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present;
} __attribute__((__packed__)) dot11_rhdr;


/**
 * @brief beacon frame 구조체.
 * 
 */
typedef struct ieee80211_beacon_frame {
    uint16_t        it_frame_control_field;
    uint16_t        it_duration;
    uint8_t            it_destination_address[6];
    uint8_t            it_source_address[6];
    uint8_t            it_bss_id[6];
    uint16_t        it_fragment_sequence_number;
} __attribute__((__packed__)) dot11_bhdr;


/**
 * @brief wireless management 구조체.
 * 
 */
typedef struct ieee80211_wireless_management_header {
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capabilities_information;
} __attribute__((__packed__)) dot11_whdr;


/**
 * @brief Radiotap Header 파싱용 클래스.
 * 
 */
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
    /**
     * @brief 생성자.
     * 
     * @param _radiotap_header_addr Radiotap Header 시작 주소. (패킷의 시작 주소와 동일)
     */
    RadiotapParser(uint8_t* _radiotap_header_addr);


    /**
     * @brief 소멸자.
     * 
     */
    ~RadiotapParser();

    
    /**
     * @brief Radiotap Header의 revision을 반환.
     * 
     * @return uint8_t 
     */
    uint8_t get_header_version();
    

    /**
     * @brief Radiotap Header의 padding을 반환.
     * 
     * @return uint8_t 
     */
    uint8_t get_header_padding();
    

    /**
     * @brief Radiotap Header의 length를 반환.
     * 
     * @return uint16_t 
     */
    uint16_t get_header_length();


    /**
     * @brief Radiotap Header의 첫 번째 present 값을 반환.
     * 
     * @return uint32_t 
     */
    uint32_t get_first_present();


    /**
     * @brief Radiotap Header의 모든 present들을 순서대로 정리한 vector의 형태로 반환.
     * 
     * @return std::vector<uint32_t> 
     */
    std::vector<uint32_t> get_presents();


    /**
     * @brief 현재 Radiotap Header에서 가지고 있는 Present Flag의 이름과 값을 map의 형태로 반환.
     *  사용법 예시: uint32_t radiotap_channel_value = get_radiotap_data_map().at(IEEE80211_RADIOTAP_CHANNEL);
     * 
     * @return std::map<dot11_relem_enum, uint32_t> 
     */
    std::map<dot11_relem_enum, uint32_t> get_radiotap_data_map();
};
