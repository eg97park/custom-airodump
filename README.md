# custom-airodump
## Test Cases
* 구현 목표
    * 출력
        * [x] BSSID
        * [x] PWR
        * [x] BEACONS
        * [x] CH
        * [x] ESSID
        * [ ] #DATA
        * [ ] ENC
    * 기능
        * [x] messed radiotap data(present)
        * [ ] channel hopping
* https://gilgil.gitlab.io/2020/09/07/1.html
    * [x] 80211-sample.pcap
    * [x] 80211-icmp.pcap
    * [x] 80211-sample1.pcap
    * [x] 80211-sample2.pcap
    * [x] 80211-sample3.pcap
* https://gitlab.com/gilgil/g/-/archive/master/g-master.zip?path=bin/pcap/dot11
    * [ ] beacon-a2000ua-testap.pcap
    * [ ] beacon-a2000ua-testap5g.pcap
    * [x] beacon-awus051nh-testap.pcap
    * [x] beacon-awus051nh-testap5g.pcap
    * [ ] beacon-forcerecon-testap.pcap
    * [ ] beacon-forcerecon-testap5g.pcap
    * [x] beacon-galaxy7-testap.pcap
    * [x] beacon-galaxy7-testap5g.pcap
    * [x] beacon-nexus5-testap.pcap
    * [x] beacon-nexus5-testap5g.pcap
    * [x] dot11-sample.pcap
---
## 요구사항
* airodump-ng와 비슷한 출력을 할 수 있는 프로그램을 작성하라.

## 세부사항
### 세부
* https://gitlab.com/gilgil/sns/-/wikis/monitor-mode/monitor-mode
* https://gitlab.com/gilgil/sns/-/wikis/dot11-frame/dot11-frame
* https://gitlab.com/gilgil/sns/-/wikis/dot11-frame/report-airodump

### 참고 URL
* https://gitlab.com/gilgil
    * 요구사항 https://gitlab.com/gilgil/sns/-/wikis/dot11-frame/report-airodump
    * 테스트용 pcap 샘플 https://gitlab.com/gilgil/g/-/tree/master/bin/pcap/dot11
    * ```void dump(void* p, size_t n)``` https://gitlab.com/gilgil/sns/-/wikis/byte-order/byte-order
    * 가상 어댑터 생성, 테스트용 pcap 샘플 https://gilgil.gitlab.io/2020/09/07/1.html
* https://www.radiotap.org/
    * ```typedef struct radiotap_align_size``` https://github.com/radiotap/radiotap-library/blob/master/radiotap_iter.h
    * ```typedef enum ieee80211_radiotap_presence``` https://github.com/radiotap/radiotap-library/blob/master/radiotap.h
    * ```static const dot11_relem_align_size dot11_relem_get_align_size``` https://github.com/radiotap/radiotap-library/blob/master/radiotap.c
* ```static const char* cvt_enum_to_str[]``` https://linuxhint.com/cpp-ways-to-convert-enum-to-string/
* ```int parse_frequency(int frequency)``` https://biig.tistory.com/84