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

	int beacon_count = 1;
	printf("CHANNEL\tBSSID\t\t\tBeacons\tFrequency\tESSID\n");
	while (true) {
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
			continue;
		}

		size_t present_count = 1;
		void* start_present = &(pkthdr_radiotap->it_present);
		RadiotapParser rtparser = RadiotapParser((void*)packet);
		if (rtparser.get_header_length() == 13){
			continue;
		}

		//printf("dump((void*)packet)\n");
		//dump((void*)packet, rtparser.get_header_length());
		printf("hdr_ver=%d\thdr_pad=%d\thdr_len=%d\tfirst_present=%08x\n", rtparser.get_header_version(), rtparser.get_header_padding(), rtparser.get_header_length(), rtparser.get_first_present());
		std::vector<uint32_t> presents_vector = rtparser.get_presents();
		for (std::vector<uint32_t>::iterator it = presents_vector.begin(); it != presents_vector.end(); it++)
		{
			printf("present[%d] = %08x\n", it - presents_vector.begin(), *it);
		}
		
		void* current_present = start_present;
		while (true)
		{
			if (*(uint32_t*)(current_present) >> 31 == 0){
				break;
			}
			uint8_t present_channel_flag = (*(uint32_t*)(current_present) >> 3) % 2;
			current_present = current_present + sizeof(uint32_t);
			present_count++;
		}

		size_t present_padding_size = 4 * ((present_count - 1) % 2);
		size_t present_total_size = 4 * (present_count) + present_padding_size;
		size_t length_from_present_to_channel = present_total_size;

		const size_t radiotap_TSFT_size = 8;
		const size_t radiotap_Flags_size = 1;
		const size_t radiotap_Rate_size = 1;

		// TSFT check
		if ((*(uint32_t*)(start_present) >> 0) % 2 == 1)
		{
			length_from_present_to_channel += radiotap_TSFT_size;
		}

		// Flags check
		if ((*(uint32_t*)(start_present) >> 1) % 2 == 1)
		{
			length_from_present_to_channel += radiotap_Flags_size;
		}

		// Rate check
		if ((*(uint32_t*)(start_present) >> 2) % 2 == 1)
		{
			length_from_present_to_channel += radiotap_Rate_size;
		}
		
		//dump(start_present, length_from_present_to_channel);
		uint16_t channel_frequency = *(uint16_t*)(start_present + length_from_present_to_channel);
		uint16_t channel_flags = *(uint16_t*)(start_present + length_from_present_to_channel + sizeof(uint16_t));
		//dump(&channel_frequency, sizeof(uint16_t));
		//dump(&channel_flags, sizeof(uint16_t));
		
		// GHz check
		/*
		bool is_2ghz = (channel_flags >> 7) % 2;
		bool is_5ghz = (channel_flags >> 8) % 2;
		*/
		char* bssid_str = parse_mac_addr(pkthdr_beacon_frame_header->it_bss_id);
		
		const size_t fixed_params_size = 12;
		const size_t tag_number_size = 1;
		const size_t tag_length_size = 1;
		dot11_whdr* pkthdr_beacon_management_header = (dot11_whdr*)(packet + pkthdr_radiotap->it_len + sizeof(struct ieee80211_beacon_frame_header));
		void* wireless_management_header = pkthdr_beacon_management_header;
		size_t ssid_length = *(uint8_t*)(wireless_management_header + fixed_params_size + tag_number_size);

		char* ssid_str = (char*)malloc(sizeof(char) * ssid_length);
		memcpy(ssid_str, (uint8_t*)(wireless_management_header + fixed_params_size + tag_number_size + tag_length_size), ssid_length);
		print_info(channel_frequency, bssid_str, beacon_count, ssid_str);
		beacon_count++;
	}

	pcap_close(pcap);
}
