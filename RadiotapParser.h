#include <cstdio>
#include <cstdlib>
#include <cstdint>

typedef struct ieee80211_radiotap_header {
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present;
} __attribute__((__packed__)) dot11_radio_hdr;

class RadiotapParser
{
private:
    void* pkt_addr;

    uint8_t hdr_ver;
    uint8_t hdr_pad;
    uint16_t hdr_len;

    void* hdr_pst_addr;
public:
    RadiotapParser(void* _radiotap_header_addr);
    ~RadiotapParser();
    uint8_t get_header_version();
    uint8_t get_header_padding();
    uint16_t get_header_length();
    uint32_t get_first_present();
};