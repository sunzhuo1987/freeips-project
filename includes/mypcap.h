#ifndef __MYPCAP_H
#define __MYPCAP_H

void pcap_callback(u_char *burb,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void pcap_listen_loop(void *handle);
pcap_t * pcap_open_device(char *dev, char *filter);
pcap_t * pcap_open_file(char *infile, char *filter);
char * pcap_return_device ();

#endif
