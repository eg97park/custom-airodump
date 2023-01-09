#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>


/**
 * @brief 사용법을 출력하는 함수.
 * 
 * @param argv 
 */
void usage(char* argv[]);


/**
 * @brief 디버깅 플래그용?
 * 
 */
typedef struct {
	char* dev_;
} __attribute__((__packed__)) Param;


/**
 * @brief 주어진 인자를 파싱하여 처리하는 함수.
 * 
 * @param param ?
 * @param argc 인자 개수
 * @param argv 인자 배열
 * @return true 
 * @return false 
 */
bool parse(Param* param, int argc, char* argv[]);


/**
 * @brief 주어진 주소로부터 메모리 값을 주어진 만큼 읽어 출력하는 함수.
 * 
 * @param p 읽을 주소
 * @param n 읽을 크기
 * 
 * @ref https://gitlab.com/gilgil/sns/-/wikis/byte-order/byte-order
 */
void dump(void* p, size_t n);


/**
 * @brief 주파수를 채널로 변환해주는 함수.
 * 
 * @param frequency 주파수
 * @return int 채널
 * @ref https://biig.tistory.com/84
 */
int parse_frequency(int frequency);


/**
 * @brief 메모리 값을 MAC 주소로 변환해주는 함수.
 * 
 * @param p MAC 주소 값이 있는 메모리 주소
 * @return char* MAC 주소 문자열
 */
char* parse_mac_addr(void* p);


/**
 * @brief airodump와 유사하게 정보를 출력하는 함수.
 * 
 * @param bssid BSSID
 * @param pwr POWER
 * @param beacons BEACON 개수
 * @param ch 채널
 * @param freq 주파수
 * @param essid ESSID
 */
void print_info(char* bssid, int pwr, int beacons, int ch, int freq, char* essid);
