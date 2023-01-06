#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#pragma pack(1)

struct ieee80211_radiotap_header {
    u_int8_t        it_version;     /* set to 0 */
    u_int8_t        it_pad;
    u_int16_t       it_len;         /* entire length */
    u_int32_t       it_present;     /* fields present */
} __attribute__((__packed__));

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
	uint8_t tagged_params_start;
} __attribute__((__packed__));

void dump(void* p, size_t n) {
	uint8_t* u8 = static_cast<uint8_t*>(p);
	size_t i = 0;
	while (true) {
		printf("%02X ", *u8++);
		if (++i >= n) break;
		if (i % 8 == 0) printf(" ");
		if (i % 16 == 0) printf("\n");
	}
	printf("\n");
}

void print_mac_address(void* p) {
	size_t mac_address_size = 6;
	uint8_t* u8 = static_cast<uint8_t*>(p);
	size_t i = 0;
	while (true) {
		printf("%02X", *u8++);
		if (i != mac_address_size - 1) printf(":");
		if (++i >= mac_address_size) break;
	}
	printf("\n");
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
		
		printf("[%d] Beacon Packet Information\n", beacon_count);
		printf("\tBSSID: ");
		print_mac_address(pkthdr_beacon_frame_header->it_bss_id);
		
		printf("\tSSID: ");
		const size_t fixed_params_size = 12;
		struct ieee80211_wireless_management_header* pkthdr_beacon_management_header = (struct ieee80211_wireless_management_header*)(packet + pkthdr_radiotap->it_len + sizeof(struct ieee80211_beacon_frame_header));
		void* wireless_management_header = pkthdr_beacon_management_header;
		size_t ssid_length = *(uint8_t*)(wireless_management_header + fixed_params_size + 1);
		for (size_t i = 0; i < ssid_length; i++)
		{
			printf("%c", *(uint8_t*)(wireless_management_header + fixed_params_size + 2 + i));
		}
		printf("\n\n");
		beacon_count++;
	}

	pcap_close(pcap);
}
