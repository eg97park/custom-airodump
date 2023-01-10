#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <memory.h>

#include "tools.h"
#include "RadiotapParser.h"


int main(int argc, char* argv[]) {
    Param param = {
        .dev_ = NULL
    };

    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    std::map<uint64_t, airodump_elem> airodump_objects;
    while (true) {
        // 패킷 캡쳐.
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        dot11_rhdr* pkthdr_radiotap = (dot11_rhdr*)packet;
        dot11_bhdr* pkthdr_beacon_frame_header = (dot11_bhdr*)(packet + pkthdr_radiotap->it_len);
        uint8_t frame_control_field_type = (uint8_t)(pkthdr_beacon_frame_header->it_frame_control_field);
        
        // Beacon frame, Daa frame 체크.
        if (frame_control_field_type != TYPE_BEACON_FRAME && frame_control_field_type != TYPE_DATA_FRAME){
            continue;
        }

        uint8_t present_count = 1;
        uint8_t* start_present = (uint8_t*)(&(pkthdr_radiotap->it_present));
        RadiotapParser rtparser = RadiotapParser((uint8_t*)packet);
        if (rtparser.get_header_length() == 13){
            // 뭔지는 모르겠는데, Wireshark에 뜨지 않는 패킷이 잡힘. 이런 패킷들은 무시.
            continue;
        }

        // Radiotap presents 및 data field 파싱.
        std::vector<uint32_t> presents_vector = rtparser.get_presents();
        std::map<dot11_relem_enum, uint32_t> rtap_map = rtparser.get_radiotap_data_map();

        // 채널 관련 처리.
        uint16_t channel_frequency = 0;
        uint16_t channel_number = 0;
        std::map<dot11_relem_enum, uint32_t>::iterator is_exists_channel = rtap_map.find(IEEE80211_RADIOTAP_CHANNEL);
        if (is_exists_channel != rtap_map.end())
        {
            channel_frequency = rtap_map.at(IEEE80211_RADIOTAP_CHANNEL);
            channel_number = parse_frequency(channel_frequency);
        }

        // 신호 관련 처리.
        int8_t antenna_signal = 0;
        std::map<dot11_relem_enum, uint32_t>::iterator is_exists_antsignal = rtap_map.find(IEEE80211_RADIOTAP_DBM_ANTSIGNAL);
        if (is_exists_antsignal != rtap_map.end())
        {
            antenna_signal = rtap_map.at(IEEE80211_RADIOTAP_DBM_ANTSIGNAL);
        }
        
        if (frame_control_field_type == TYPE_BEACON_FRAME)
        {
            // BSSID 관련 처리.
            uint64_t bssid_value = 0;
            uint8_t* bssid = pkthdr_beacon_frame_header->it_bss_id;
            std::memcpy(&bssid_value, bssid, sizeof(uint8_t) * 6);
            
            // SSID 길이 관련 처리.
            dot11_whdr* pkthdr_beacon_management_header = (dot11_whdr*)(packet + pkthdr_radiotap->it_len + sizeof(dot11_bhdr));
            uint8_t* wireless_management_header = (uint8_t*)pkthdr_beacon_management_header;
            uint8_t ssid_length = *(wireless_management_header + DOT11_WLANM_FIXED_PARAM_SIZE + DOT11_WLANM_TAG_NUMBER_SIZE);
            char* ssid_str = nullptr;
            if (ssid_length != 0)
            {
                if (MAX_SSID_LENGTH < ssid_length)
                {
                    ssid_length = MAX_SSID_LENGTH;
                }
                ssid_str = (char*)malloc(sizeof(char) * ssid_length + 1);
                memcpy(ssid_str, (char*)(wireless_management_header + DOT11_WLANM_FIXED_PARAM_SIZE + DOT11_WLANM_TAG_NUMBER_SIZE + DOT11_WLANM_TAG_LENGTH_SIZE), ssid_length);
                ssid_str[sizeof(char) * ssid_length] = '\x00';
            }

            std::map<uint64_t, airodump_elem>::iterator bssid_finder = airodump_objects.find(bssid_value);
            if (bssid_finder != airodump_objects.end())
            {
                (*bssid_finder).second.pwr = antenna_signal;
                (*bssid_finder).second.ch = channel_number;
                (*bssid_finder).second.freq = channel_frequency;
                (*bssid_finder).second.essid = ssid_str;
                (*bssid_finder).second.beacons += 1;
            }
            else
            {
                airodump_elem new_airodump_elem = {
                    .bssid = bssid_value,
                    .pwr = antenna_signal,
                    .ch = channel_number,
                    .freq = channel_frequency,
                    .essid = ssid_str,
                    .beacons = 1,
                    .datas = 0
                };
                airodump_objects.insert(
                    std::pair<uint64_t, airodump_elem>(bssid_value, new_airodump_elem)
                );
            }
        }
        else if (frame_control_field_type == TYPE_DATA_FRAME)
        {
            // BSSID 관련 처리.
            dot11_dhdr* pkthdr_data_frame_header = (dot11_dhdr*)(packet + pkthdr_radiotap->it_len);
            uint64_t bssid_value = 0;
            uint8_t* bssid = pkthdr_data_frame_header->it_bss_id;
            std::memcpy(&bssid_value, bssid, sizeof(uint8_t) * 6);

            std::map<uint64_t, airodump_elem>::iterator bssid_finder = airodump_objects.find(bssid_value);
            if (bssid_finder != airodump_objects.end())
            {
                (*bssid_finder).second.pwr = antenna_signal;
                (*bssid_finder).second.ch = channel_number;
                (*bssid_finder).second.freq = channel_frequency;
                (*bssid_finder).second.datas += 1;
            }
            else
            {
                airodump_elem new_airodump_elem = {
                    .bssid = bssid_value,
                    .pwr = antenna_signal,
                    .ch = channel_number,
                    .freq = channel_frequency,
                    .essid = nullptr,
                    .beacons = 0,
                    .datas = 1
                };
                airodump_objects.insert(
                    std::pair<uint64_t, airodump_elem>(bssid_value, new_airodump_elem)
                );
            }
        }
        
        // 출력.
        print_info_map(airodump_objects);
    }
    pcap_close(pcap);
}
