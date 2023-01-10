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

	const uint8_t fixed_params_size = 12;
	const uint8_t tag_number_size = 1;
	const uint8_t tag_length_size = 1;

	printf("BSSID\t\t\tPWR\tCH\tFREQ\tESSID\t\t\t\t\t#BEACON\t#DATA\n");

	int data_count = 0;
	int beacon_count = 0;
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
		if (pkthdr_beacon_frame_header->it_frame_control_field != 0x0080){
			// Beacon frame이 아니라면, 무시.
			data_count++;
			continue;
		}
		beacon_count++;

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
		
		// BSSID 관련 처리.
		char* bssid_str = parse_mac_addr(pkthdr_beacon_frame_header->it_bss_id);
		
		// SSID 길이 관련 처리.
		dot11_whdr* pkthdr_beacon_management_header = (dot11_whdr*)(packet + pkthdr_radiotap->it_len + sizeof(dot11_bhdr));
		uint8_t* wireless_management_header = (uint8_t*)pkthdr_beacon_management_header;
		uint8_t ssid_length = *(wireless_management_header + fixed_params_size + tag_number_size);

		// SSID 관련 처리.
		const int MAX_SSID_LENGTH = 32;
		char* ssid_str = nullptr;
		if (ssid_length != 0)
		{
			if (MAX_SSID_LENGTH < ssid_length)
			{
				ssid_length = MAX_SSID_LENGTH;
			}
			ssid_str = (char*)malloc(sizeof(char) * ssid_length + 1);
			memcpy(ssid_str, (char*)(wireless_management_header + fixed_params_size + tag_number_size + tag_length_size), ssid_length);
			ssid_str[sizeof(char) * ssid_length] = '\x00';
		}

		// 정보 출력.
		print_info(bssid_str, antenna_signal, channel_number, channel_frequency, ssid_str, beacon_count, 0);
	}

	pcap_close(pcap);
}
