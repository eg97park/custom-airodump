#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <memory.h>

#include "tools.h"
#include "RadiotapParser.h"

#pragma pack(1)

struct ieee80211_beacon_frame_header {
    uint16_t		it_frame_control_field;
    uint16_t		it_duration;
    uint8_t			it_destination_address[6];
    uint8_t			it_source_address[6];
    uint8_t			it_bss_id[6];
    uint16_t		it_fragment_sequence_number;
} __attribute__((__packed__));

struct ieee80211_wireless_management_header {
	uint64_t timestamp;
	uint16_t beacon_interval;
	uint16_t capabilities_information;
} __attribute__((__packed__));

char* parse_mac_addr(void* p) {
	uint8_t* u8 = static_cast<uint8_t*>(p);
	char* buffer = (char*)malloc(sizeof(char) * 18);
	snprintf(buffer, 18, "%02X:%02X:%02X:%02X:%02X:%02X", u8[0], u8[1], u8[2], u8[3], u8[4], u8[5]);
	return buffer;
}

void usage(char* argv[]) {
	printf("syntax: %s <interface>\n", argv[0]);
	printf("sample: %s wlp45s0\n", argv[0]);
}

typedef struct {
	char* dev_;
} __attribute__((__packed__)) Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage(argv);
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

// https://biig.tistory.com/84
int parse_frequency(int frequency){
	if(frequency >= 2412 && frequency <= 2484) {
		if (frequency == 2484)
			return (frequency - 2412) / 5;
		return (frequency - 2412) / 5 + 1;
	}
	else if(frequency >= 5170 && frequency <= 5825) {
		return (frequency - 5170) / 5 + 34;
	}
	else {
		return -1;
	}
}

void print_info(int frequency, char* bssid, int beacons, char* essid) {
	int channel = parse_frequency(frequency);
	printf("%d\t%s\t%d\t%dGHz\t\t%s\n", channel, bssid, beacons, frequency, essid);
	return;
}

int main(int argc, char* argv[]) {
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

		struct ieee80211_radiotap_header* pkthdr_radiotap = (struct ieee80211_radiotap_header*)packet;
		struct ieee80211_beacon_frame_header* pkthdr_beacon_frame_header = (struct ieee80211_beacon_frame_header*)(packet + pkthdr_radiotap->it_len);
		if (pkthdr_beacon_frame_header->it_frame_control_field != 0x0080){
			continue;
		}

		size_t present_count = 1;
		void* start_present = &(pkthdr_radiotap->it_present);
		RadiotapParser rtparser = RadiotapParser((void*)packet);
		printf("hdr_ver=%d\n", rtparser.get_header_version());
		printf("hdr_pad=%d\n", rtparser.get_header_padding());
		printf("hdr_len=%d\n", rtparser.get_header_length());
		printf("first_present=%08x\n", rtparser.get_first_present());
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
		struct ieee80211_wireless_management_header* pkthdr_beacon_management_header = (struct ieee80211_wireless_management_header*)(packet + pkthdr_radiotap->it_len + sizeof(struct ieee80211_beacon_frame_header));
		void* wireless_management_header = pkthdr_beacon_management_header;
		size_t ssid_length = *(uint8_t*)(wireless_management_header + fixed_params_size + tag_number_size);

		char* ssid_str = (char*)malloc(sizeof(char) * ssid_length);
		memcpy(ssid_str, (uint8_t*)(wireless_management_header + fixed_params_size + tag_number_size + tag_length_size), ssid_length);
		print_info(channel_frequency, bssid_str, beacon_count, ssid_str);
		beacon_count++;
	}

	pcap_close(pcap);
}
