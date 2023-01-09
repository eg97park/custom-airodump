#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

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

void print_info(char* bssid, int pwr, int beacons, int ch, char* essid);