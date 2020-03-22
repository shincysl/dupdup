#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <libnet.h>
#include <time.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 65535

#ifdef COOKED
	#define ETHERNET_H_LEN 16
#else
	#define ETHERNET_H_LEN 14
#endif

#define SPECIAL_TTL 80
#define BW_ESTIMATE_SIZE 3

int bwestimate_byte[BW_ESTIMATE_SIZE];
int bwestimate_time[BW_ESTIMATE_SIZE];
int bwestimate_packet = 0;
int bwestimate_result = 0;

int throttle_low = 512;
int throttle_median = 1024;

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_usage(void);
void estimate_bandwidth(struct libnet_ipv4_hdr *ip);
char estimate_ok(void);


/*
 * print help text
 */
void print_usage(void) {
	printf("Usage: %s [interface][\"filter rule\"] [low] [med]\n", "dupdup");
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("    filter       Rules to filter packets.\n");
	printf("\n");
}

void estimate_bandwidth(struct libnet_ipv4_hdr *ip) {
	int now = (int)time(0); // truncated
	int fract = now % BW_ESTIMATE_SIZE;
	int whole = now / BW_ESTIMATE_SIZE;

	// Out-of-date
	for (int i = 0; i < BW_ESTIMATE_SIZE; i++) {
		if (bwestimate_time[i] > 0 && whole - bwestimate_time[i] > 1) {
			bwestimate_time[i] = 0;
			bwestimate_byte[i] = 0;
		}
	}
	if (bwestimate_time[fract] != whole) {
		bwestimate_time[fract] = 0;
		bwestimate_byte[fract] = 0;
	}

	// Accumulate
	bwestimate_time[fract] = whole;
	bwestimate_byte[fract] += ntohs(ip->ip_len);

	// Mean BW
	int mean = 0;
	for (int i = 0; i < BW_ESTIMATE_SIZE; i++) {
		mean += bwestimate_byte[i];
	}
	bwestimate_result = mean / BW_ESTIMATE_SIZE;
	bwestimate_packet++;
}

char estimate_ok() {
	int kbytes = bwestimate_result / 1024;
	if (kbytes < throttle_low) {
		return 0;
	} else if (kbytes < throttle_median) {
		return bwestimate_packet % 2;
	} else {
		return 127;
	}
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	static int count = 1;                  
	struct libnet_ipv4_hdr *ip;              

	libnet_t *libnet_handler = (libnet_t *)args;
	count++;
	
	ip = (struct libnet_ipv4_hdr*)(packet + ETHERNET_H_LEN);

	if(ip->ip_ttl != SPECIAL_TTL) {
		estimate_bandwidth(ip);
		if (estimate_ok() != 0) {
			return;
		}

		ip->ip_ttl = SPECIAL_TTL;
		ip->ip_sum = 0;
		if(ip->ip_p == IPPROTO_TCP) {
			struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr *)((u_int8_t *)ip + ip->ip_hl * 4);
			tcp->th_sum = 0;
			libnet_do_checksum(libnet_handler, (u_int8_t *)ip, IPPROTO_TCP, LIBNET_TCP_H);
		} else if(ip->ip_p == IPPROTO_UDP) {
			struct libnet_udp_hdr *udp = (struct libnet_udp_hdr *)((u_int8_t *)ip + ip->ip_hl * 4);
			udp->uh_sum = 0;
			libnet_do_checksum(libnet_handler, (u_int8_t *)ip, IPPROTO_UDP, LIBNET_UDP_H);
		}
		int len_written = libnet_adv_write_raw_ipv4(libnet_handler, (u_int8_t *)ip, ntohs(ip->ip_len));
		if(len_written < 0) {
			printf("packet len:[%d] actual write:[%d]\n", ntohs(ip->ip_len), len_written);
			printf("err msg:[%s]\n", libnet_geterror(libnet_handler));
		}
	} else {
		//The packet dupdup sent. nothing todo
	}
	return;
}

libnet_t* start_libnet(char *dev) {
	char errbuf[LIBNET_ERRBUF_SIZE];
	libnet_t *libnet_handler = libnet_init(LIBNET_RAW4_ADV, dev, errbuf);

	if(NULL == libnet_handler) {
		printf("libnet_init: error %s\n", errbuf);
	}
	return libnet_handler;
}

#define ARGC_NUM 5
int main(int argc, char **argv) {
	char *dev = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	char *filter_rule = NULL;
	struct bpf_program fp;
	bpf_u_int32 net, mask;

	if (argc == ARGC_NUM) {
		dev = argv[1];
		filter_rule = argv[2];
		throttle_low = atoi(argv[3]);
		throttle_median = atoi(argv[4]);
		printf("Device: %s\n", dev);
		printf("Filter rule: %s\n", filter_rule);
		printf("100%%: 0 - %d kbytes\n", throttle_low);
		printf("50%%: %d - %d kbytes\n", throttle_low, throttle_median);
	} else {
		print_usage();	
		return -1;
	}
	
	printf("ethernet header len:[%d](14:normal, 16:cooked)\n", ETHERNET_H_LEN);

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		printf("Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	printf("init pcap\n");
	handle = pcap_open_live(dev, SNAP_LEN, 1, 0, errbuf);
	if(handle == NULL) {
		printf("pcap_open_live dev:[%s] err:[%s]\n", dev, errbuf);
		printf("init pcap failed\n");
		return -1;
	}

	printf("init libnet\n");
	libnet_t *libnet_handler = start_libnet(dev);
	if(NULL == libnet_handler) {
		printf("init libnet failed\n");
		return -1;
	}

	if (pcap_compile(handle, &fp, filter_rule, 0, net) == -1) {
		printf("filter rule err:[%s][%s]\n", filter_rule, pcap_geterr(handle));
		return -1;
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		printf("set filter failed:[%s][%s]\n", filter_rule, pcap_geterr(handle));
		return -1;
	}

	while(1) {
		pcap_loop(handle, 1, got_packet, (u_char *)libnet_handler);
	}

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);
	libnet_destroy(libnet_handler);
	return 0;
}
