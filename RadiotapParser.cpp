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


std::map<dot11_relem_enum, uint32_t> RadiotapParser::get_radiotap_data_map()
{
    if (!this->rtap_data_map.empty())
    {
        return this->rtap_data_map;
    }

    if (this->rtap_present_vector.empty())
    {
        this->get_presents();
    }

    std::vector<dot11_relem_enum> bit_sequence_vector;
	for (std::vector<uint32_t>::iterator it = this->rtap_present_vector.begin(); it != this->rtap_present_vector.end(); it++)
	{
        uint32_t curent_present = *it;
        for (size_t i = IEEE80211_RADIOTAP_TSFT; i < IEEE80211_RADIOTAP_EXT + 1; i++)
        {
            uint8_t currnet_bit = ((*it) >> i) % 2;
            if (currnet_bit == 1 && i < IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE)
            {
                bit_sequence_vector.push_back(dot11_relem_enum(i));
            }
        }
	}

    uint8_t addr_gap = (
        sizeof(((dot11_rhdr*)nullptr)->it_version) +
        sizeof(((dot11_rhdr*)nullptr)->it_pad) +
        sizeof(((dot11_rhdr*)nullptr)->it_len)
    ) + (
        this->rtap_present_vector.size() * sizeof(uint32_t)
    );

	for (std::vector<dot11_relem_enum>::iterator it = bit_sequence_vector.begin(); it != bit_sequence_vector.end(); it++)
	{
        uint8_t relem_size = (dot11_relem_get_align_size[*it]).size;
        uint8_t relem_align = (dot11_relem_get_align_size[*it]).align;
        
        if (addr_gap % relem_align != 0)
        {
            uint8_t pad_size_cand = relem_align - (addr_gap % relem_align);
            addr_gap = addr_gap + pad_size_cand;
        }
        
        uint64_t relem_value = 0;
        std::memcpy(&relem_value, this->pkt_addr + addr_gap, sizeof(uint8_t) * relem_size);
        this->rtap_data_map.insert(std::pair<dot11_relem_enum, uint64_t>(*it, relem_value));
        addr_gap += relem_size;
	}

    return this->rtap_data_map;
}
