#include "RadiotapParser.h"
#include "tools.h"


RadiotapParser::RadiotapParser(void* _pkt_addr)
{
    this->pkt_addr = _pkt_addr;

    dot11_rhdr* hdr = (dot11_rhdr*)this->pkt_addr;
    this->hdr_ver = hdr->it_version;
    this->hdr_pad = hdr->it_pad;
    this->hdr_len = hdr->it_len;
    this->hdr_pst_addr = &(hdr->it_present);
}

RadiotapParser::~RadiotapParser()
{
}

uint8_t RadiotapParser::get_header_version()
{
    return this->hdr_ver;
}

uint8_t RadiotapParser::get_header_padding()
{
    return this->hdr_pad;
}

uint16_t RadiotapParser::get_header_length()
{
    return this->hdr_len;
}

uint32_t RadiotapParser::get_first_present()
{
    uint32_t first_present = *((uint32_t*)hdr_pst_addr);
    return first_present;
}

/**
 * present 필드 뒤에 오는 radiotap data의 경우,
 * 크기에 따라 패딩 길이가 달라짐.
 * 
 * 만약 MAC timestamp와 같이 8bytes 크기 필드가 온다면,
 * 8bytes 단위부터 시작해야 함.
 * 예제: 80211-sample.pcap
 *  MAC timestamp -> Flags -> ...
 * 
 * 만약 Flags와 같이 4bytes 크기 필드가 온다면,
 * 4bytes 단위부터 시작해야 함.
 * 예제: 80211-sample1.pcap
 *  Flags -> ...
*/
std::vector<uint32_t> RadiotapParser::get_presents()
{
    std::vector<uint32_t> presents_vals;
    uint32_t* present_addr = (uint32_t*)(this->hdr_pst_addr);
    size_t presents_count = 1;
    while (true)
    {
        presents_vals.push_back(*present_addr);
        if ((*present_addr) >> 31 == 0)
        {
            break;
        }
        presents_count++;
        present_addr = present_addr + 1;
    }
    return presents_vals;
}

std::map<dot11_relem_enum, uint64_t> RadiotapParser::get_radiotap_data_map()
{
    if (!this->rtap_data_map.empty())
    {
        return this->rtap_data_map;
    }
    /* Do something... */

    return this->rtap_data_map;
}