#ifndef __MAIN_H
#define __MAIN_H

int destructor_callback (void *data,struct list_entry *entry);
int traffic_analyzer(void *data,struct list_entry *entry);
char * resolve_ip (char *ip);
void sighandler();

#define DNS_NAME_SIZE		64
#define ETHER_ADDR_LEN          6
#define SNAPLEN			65535

struct iphdr
  {
#if BYTE_ORDER == LITTLE_ENDIAN
      unsigned int ip_hl:4;               /* header length */
      unsigned int ip_v:4;                /* version */
#endif
#if BYTE_ORDER == BIG_ENDIAN
      unsigned int ip_v:4;                /* version */
      unsigned int ip_hl:4;               /* header length */
#endif
      u_int8_t ip_tos;                    /* type of service */
      u_short ip_len;                     /* total length */
      u_short ip_id;                      /* identification */
      u_short ip_off;                     /* fragment offset field */
#define IP_RF 0x8000                      /* reserved fragment flag */
#define IP_DF 0x4000                      /* dont fragment flag */
#define IP_MF 0x2000                      /* more fragments flag */
#define IP_OFFMASK 0x1fff                 /* mask for fragmenting bits */
      u_int8_t ip_ttl;                    /* time to live */
      u_int8_t ip_p;                      /* protocol */
      u_short ip_sum;                     /* checksum */
      struct in_addr ip_src, ip_dst;      /* source and dest address */
};


struct ether_header {
        u_char  ether_dhost[ETHER_ADDR_LEN];
        u_char  ether_shost[ETHER_ADDR_LEN];
        u_short ether_type;
};


#endif
