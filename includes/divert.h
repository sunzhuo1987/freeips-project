#ifndef __DIVERT_H
#define __DIVERT_H

#define DIVERT_PACKET_SIZE 65535

void divert_open_socket(int port);
void divert_listen_loop();
int divert_inject( struct traffic *traf);

#endif
