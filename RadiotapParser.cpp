#include "RadiotapParser.h"
#include "tools.h"


RadiotapParser::RadiotapParser(uint8_t* _pkt_addr)
{
    this->pkt_addr = _pkt_addr;

    dot11_rhdr* hdr = (dot11_rhdr*)this->pkt_addr;
    this->hdr_ver = hdr->it_version;
    this->hdr_pad = hdr->it_pad;
    this->hdr_len = hdr->it_len;
    this->hdr_pst_addr = (uint8_t*)(&(hdr->it_present));
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
    if (!this->rtap_present_vector.empty())
    {
        return this->rtap_present_vector;
    }

    uint8_t* present_addr = this->hdr_pst_addr;
    size_t presents_count = 1;
    while (true)
    {
        uint32_t present_value = *(uint32_t*)present_addr;
        this->rtap_present_vector.push_back(present_value);
        if (present_value >> IEEE80211_RADIOTAP_EXT == 0)
        {
            break;
        }
        presents_count++;
        present_addr = present_addr + sizeof(uint32_t);
    }
    return this->rtap_present_vector;
}

std::map<dot11_relem_enum, uint64_t> RadiotapParser::get_radiotap_data_map()
{
    if (!this->rtap_data_map.empty())
    {
        return this->rtap_data_map;
    }

    if (this->rtap_present_vector.empty())
    {
        this->get_presents();
    }

    /* Do something... */
    // 모든 present 탐색, flag 순서 획득.
    std::vector<dot11_relem_enum> bit_sequence_vector;
	for (std::vector<uint32_t>::iterator it = this->rtap_present_vector.begin(); it != this->rtap_present_vector.end(); it++)
	{
        uint32_t curent_present = *it;
        for (size_t i = IEEE80211_RADIOTAP_TSFT; i < IEEE80211_RADIOTAP_EXT + 1; i++)
        {
            uint8_t currnet_bit = ((*it) >> i) % 2;
            if (currnet_bit == 1 && i < IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE)
            {
                //rtap_data_map_.insert(std::pair<dot11_relem_enum, uint64_t>(dot11_relem_enum(i), ));
                bit_sequence_vector.push_back(dot11_relem_enum(i));
            }
        }
	}

    //it - bit_sequence_vector.begin()
    uint8_t addr_gap = (sizeof(((dot11_rhdr*)0)->it_version) + sizeof(((dot11_rhdr*)0)->it_pad) + sizeof(((dot11_rhdr*)0)->it_len) + (this->rtap_present_vector.size() * sizeof(uint32_t)));
    //void* last_accessed_addr = this->pkt_addr + addr_gap;
    uint8_t* last_accessed_addr = this->pkt_addr + addr_gap;
    printf("addr_gap=%d\n", addr_gap);
	for (std::vector<dot11_relem_enum>::iterator it = bit_sequence_vector.begin(); it != bit_sequence_vector.end(); it++)
	{
        /*
        index   size    addpad  todo
        12      1       0       + (size - (index % size))
        12      2       0       
        12      4       0       
        12      8       4       

        13      1       0       
        13      2       1       
        13      4       3       
        13      8       3       
        */
        uint8_t relem_size = dot11_relem_size[it - bit_sequence_vector.begin()];
        if (addr_gap % relem_size != 0)
        {
            uint8_t pad_size_cand = relem_size - (addr_gap % relem_size);
            printf("padding needed at %d, amount=%d\n", *it, pad_size_cand);
            addr_gap = addr_gap + pad_size_cand;
        }
        else
        {
            addr_gap = addr_gap + relem_size;
        }
        
        
        printf("@\t%d\t:%d\n", *it, relem_size);
	}
    
    
    // flag 순서 별 flag 크기 획득
    // 적절한 위치 지정.

    return this->rtap_data_map;
}