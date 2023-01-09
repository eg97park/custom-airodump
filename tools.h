#include <stddef.h> // for size_t
#include <stdint.h> // for uint8_t
#include <stdio.h> // for printf
#include <stdlib.h> // for printf

void usage(char* argv[]);

typedef struct {
	char* dev_;
} __attribute__((__packed__)) Param;

bool parse(Param* param, int argc, char* argv[]);

// https://gitlab.com/gilgil/sns/-/wikis/byte-order/byte-order
void dump(void* p, size_t n);

// https://biig.tistory.com/84
int parse_frequency(int frequency);

char* parse_mac_addr(void* p);

void print_info(int frequency, char* bssid, int beacons, char* essid);
