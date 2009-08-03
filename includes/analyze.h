#ifndef __ANALYZE_H
#define __ANALYZE_H

//analyzer thread
void pcap_analyzer();
int traffic_analyzer(void *data,struct list_entry *entry);


#endif
