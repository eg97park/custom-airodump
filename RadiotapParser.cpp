#include "RadiotapParser.h"
#include "tools.h"

RadiotapParser::RadiotapParser(void* _pkt_addr)
{
    this->pkt_addr = _pkt_addr;

    dot11_radio_hdr* hdr = (dot11_radio_hdr*)this->pkt_addr;
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

uint32_t* RadiotapParser::get_presents()
{
    return nullptr;
}
