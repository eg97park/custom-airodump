#include "tools.h"


void usage(char* argv[])
{
	printf("syntax: %s <interface>\n", argv[0]);
	printf("sample: %s wlp45s0\n", argv[0]);
}

bool parse(Param* param, int argc, char* argv[])
{
	if (argc != 2) {
		usage(argv);
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

// https://gitlab.com/gilgil/sns/-/wikis/byte-order/byte-order
void dump(void* p, size_t n)
{
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

// https://biig.tistory.com/84
int parse_frequency(int frequency)
{
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

char* parse_mac_addr(void* p)
{
	uint8_t* u8 = static_cast<uint8_t*>(p);
	char* buffer = (char*)malloc(sizeof(char) * 18);
	snprintf(buffer, 18, "%02X:%02X:%02X:%02X:%02X:%02X", u8[0], u8[1], u8[2], u8[3], u8[4], u8[5]);
	return buffer;
}

void print_info(char* bssid, int pwr, int beacons, int ch, char* essid)
{
	printf("%s\t%d\t%d\t%d\t%s\n", bssid, pwr, beacons, ch, essid);
	return;
}

