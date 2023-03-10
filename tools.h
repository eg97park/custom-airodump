#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include <iostream>
#include <map>


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
char* parse_mac_addr(uint8_t* p);


/**
 * @brief airodump와 유사하게 정보를 출력하는 함수.
 * 
 * @param bssid BSSID
 * @param pwr POWER
 * @param ch 채널
 * @param freq 주파수
 * @param essid ESSID
 * @param nbeacon BEACON 개수
 * @param ndata DATA 개수
 */
void print_info(uint8_t* bssid, int pwr, int ch, int freq, char* essid, int nbeacon, int ndata);


/**
 * @brief airodump 출력용 객체의 구조체.
 * 
 */
typedef struct airodump__ng_element
{
    uint64_t bssid;
    int8_t pwr;
    uint16_t ch;
    uint16_t freq;
    char* essid;
    size_t beacons;
    size_t datas;
} __attribute__((__packed__)) airodump_elem;


/**
 * @brief 콘솔 지우는 함수.
 * 
 * @ref https://stackoverflow.com/a/6487534
 */
void clear();


/**
 * @brief airodump와 유사하게 정보를 출력하는 함수.
 *  단, std::map<uint64_t, airodump_elem>을 순환하며 출력.
 * 
 * @param airodump_objects std::map of airodump_elem
 */
void print_info_map(std::map<uint64_t, airodump_elem> airodump_objects);
