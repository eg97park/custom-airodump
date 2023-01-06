# custom-airodump
## 요구사항
* airodump-ng와 비슷한 출력을 할 수 있는 프로그램을 작성하라.
## 세부사항
### 세부
* https://gitlab.com/gilgil/sns/-/wikis/monitor-mode/monitor-mode
* https://gitlab.com/gilgil/sns/-/wikis/dot11-frame/dot11-frame
* https://gitlab.com/gilgil/sns/-/wikis/dot11-frame/report-airodump

### 제목
* char name[] = "홍길동";
* char mobile[] = "8908";
* printf("[bob11]airodump[%s%s]", name, mobile);

### 기한
* 2023.01.10

### 제출
* bob@gilgil.net

### 기타
* 수업이 끝나고 질문 들어온 사항 정리해서 올립니다.
```
Q. 과제를 C가 아닌 Python으로 제출해도 됩니까?
A. 넵. 다만 scapy 모듈을 사용해서는 안됩니다.

Q. airodump-ng 명령어에서 5GHz 대역 스캔은 어떻게 합니까?
A. airodump-ng 명령어에 -bb(2.4GHz), -ba(5GHz), -bab(2.4 and 5GHz) 옵션을 주면 됩니다.

Q. Channel Hopping도 구현해야 합니까?
A. 옵션입니다. "sudo iwconfig mon0 channel 1"과 같은 명령어를 정기적으로 수행하면 Channel Hopping을 구현할 수 있습니다.

Q. Packet은 어떻게 잡을 수 있습니까?
A. pcap API를 사용하면 됩니다. 기본 skeleton code를 작성해 놓은 것이 있으니 참고하시기 바랍니다.
https://gitlab.com/gilgil/sns/-/wikis/pcap-programming/report-pcap-test
https://gitlab.com/gilgil/pcap-test

Q. 실습을 따라가려 하는데 글자가 작아서 잘 보이지 않습니다.
A. 다음부터는 실습을 할 때 터미널 글자 크기를 좀 더 크게 하도록 하겠습니다.

이번 과제는 어렵게 하려면 정말 여럽고(구조체를 이쁘게 디자인하는 것이 쉽지 않음), hard coding하면 금방 할 수도 있습니다(Radiotap Header를 skip하고 나서는 Beacon Frame에서 SSID Tag가 있는 곳의 위치가 고정되어 있음). 자신이 구현할 수 있는 정도까지 해 보시기 바랍니다.
```