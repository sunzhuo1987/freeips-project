
#ifndef __CONTROL_H
#define __CONTROL_H

#define BACKLOG 10
#define BUF_SIZE 512

#define HTTP_TYPE_TXT	1
#define HTTP_TYPE_HTML	2

void control_loop();
char extract_cmd(char *data);
int control_open_port(int port);
void send_http_response(int sock,int type, char *data);
int handle_connection( int clientfd); 
void write_file_to_fd(FILE *fd, char *filename);
int reloadSignatures();
int check_http_auth(char *readbuf, int rsize, FILE * fsock);



#endif
