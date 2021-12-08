#include <libnet.h>
#include <pcap.h>
#include <string>
#include <map>
#include <utility>
#include "mac.h"

#pragma pack(push, 1)
struct ieee80211_radiotap_header {
	u_int8_t it_version;	/* set to 0 */
	u_int8_t it_pad;
	u_int16_t it_len;		/* entire length */
	u_int32_t it_present;	/* fields present */
};
struct ieee80211_beacon_mac_header {
	uint8_t type;
	uint8_t flag;
	uint16_t duration;	// ms
	Mac da;				// destination address
	Mac sa;				// source address
	Mac bssid;
	uint16_t seq;
};
struct fixed_parameter {
	uint64_t timestamp;
	uint16_t interval;
	uint16_t cap_info;
};
struct tagged_parameter {
	uint8_t num;
	uint8_t len;
	uint8_t essid;
};
#pragma pack(pop)

using radiotap_hdr = ieee80211_radiotap_header;
using beacon_hdr = ieee80211_beacon_mac_header;
using fixed_pm = fixed_parameter;
using taged_pm = tagged_parameter;

std::map<Mac, std::pair<uint8_t, std::string>> mymap;

void usage()
{
	printf("syntax : airodump <interface>\n");
	printf("sample : airodump mon0\n");
	exit(1);
}

void myprint() {
	system("clear");
	printf("BSSID\t\t   Beacons\tESSID\n\n");
	for(auto &[i, j] : mymap) {
		printf("%s", std::string(i).c_str());
		printf("\t%d", j.first);
		printf("\t%s\n", j.second.c_str());
	}
}

int main(int argc, char *argv[]) {
	if(argc != 2)
		usage();

	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		exit(1);
	}

	struct pcap_pkthdr *header;
	const u_char *recv;
	while(1) {
		int res = pcap_next_ex(pcap, &header, &recv);
		if(res == 0) continue;
		if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			pcap_close(pcap);
			exit(1);
		}

		radiotap_hdr *radio = (radiotap_hdr *)recv;
		beacon_hdr *beacon = (beacon_hdr *) (recv + radio -> it_len);
		if(beacon -> type != 0x80) continue;

		fixed_pm *fp = (fixed_pm *)((u_char *)beacon + sizeof(beacon_hdr));
		taged_pm *tp = (taged_pm *)((u_char *)fp + sizeof(fixed_pm));
		if(tp -> num != 0) continue;

		char *ssid = (char *)tp + 2;
		std::string essid;
		for(auto i = tp -> len; i--; )
			essid += *ssid++;

		if(mymap.count(beacon -> bssid)) mymap[beacon -> bssid].first++;
		else mymap[beacon -> bssid] = {1, essid};

		myprint();
	}
	pcap_close(pcap);
	return 0;
}
