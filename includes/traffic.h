#ifndef __TRAFFIC_H
#define __TRAFFIC_H

#define TRAFFIC_TYPE_PCAP    1
#define TRAFFIC_TYPE_DIVERT  2

typedef struct traffic {
        struct in_addr ip_src;
        struct in_addr ip_dst;

        u_int8_t proto;
        int      ip_len;

        // Processed data
        struct  ether_header* ethhdr;
        struct  iphdr*   iphdr;
        struct  tcphdr*  tcphdr;
        struct  udphdr*  udphdr;
        struct  icmphdr* icmphdr;

        int type;

        // For divert
        struct sockaddr saddr;

        struct pcap_pkthdr pkthdr;
        struct signature *signature;
        void    *data;
        void    *payload;
	int	poffset;

        int     dsize;
        int     psize;
        long    hashkey;

	// Todo: generalize processed content
	// references. 

	int http_processed;
	int http_present;
	char *http_uri;

	// If set to 1 anywhere during processing -> drop packet
	int drop;
} Traffic;

void traffic_free(struct traffic *traf);
int traffic_to_file(char *file, struct traffic *traf);
struct traffic * divert_to_traffic(void *packet, int psize);
struct traffic * pcap_to_traffic(void *packet, const struct pcap_pkthdr* pkthdr);
void traffic_dump(struct traffic* traffic);
int compare_traffic_signature(struct traffic* traffic, struct signature* sret);


#endif
