//
// Copyright (c) 2006-2009 Niels Heinen
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. The name of author may not be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
// AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
// OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

#include <util.h>

extern pthread_t t_analyzer;
extern pthread_t t_control;
extern int loop_control;
extern int loop_analyzer;

// Searches for c=<val>
//
// Return values
// 0   --> No match
// 1   --> Get stats

char extract_cmd(char *data) {
	int i;
	if(strncmp(data,"GET",3) != 0) 
		return 0;

	// start at 1
	for(i=1;i<strlen(data);i++) {
		if(data[i] == '=' && data[i - 1] == 'c') {
			if(++i > strlen(data))
				return 0;

			return (char)data[i];			
		}
	}
	return '0';
}

// Check authentication

int check_http_auth(char *readbuf, int rsize, FILE * fsock) {

	char *authptr = NULL;
	authptr = strnstr(readbuf,"Authorization", rsize);

	if(authptr == NULL)
		return 1;	

	if((authptr = index(authptr,HEX_VAL_SPACE)) == NULL) {
		return 1;
	}

	// First check the Basic keyword
	if(strncmp(authptr," Basic",6) == 0) {
		authptr++; // skip the space
		if((authptr = index(authptr,HEX_VAL_SPACE)) != NULL) {
			authptr++;	
			if(strncmp(CONFIG_CONTROL_HTTP_AUTH,authptr,strlen(CONFIG_CONTROL_HTTP_AUTH)) == 0) {
				return 0;
			}  else {
				return 1;	
			}
		}
	}

	return 1;
} 

void send_http_response(int sock,int type, char *data) {
	write(sock,"HTTP/1.0 200 OK\n",18);

	if(type == HTTP_TYPE_HTML) {
		write(sock,"Content-Type: text/html",24);
	} else {
		// Assume HTTP_TYPE_TXT
		write(sock,"Content-Type: text/plain",25);
	}
	write(sock,"\n\n",2);
	write(sock,data,strlen(data));
}

void write_file_to_fd(FILE *fd, char *filename) {
	FILE *fp;
        char line[BUF_SIZE];

	if ((fp = fopen(filename, "r")) == NULL){
                fatal_error("Unable to open config file %s!\n", filename);
                return;
	}

	while(fgets(line,BUF_SIZE,fp) != NULL) {
		fprintf(fd,"%s",line);
	}
	fclose(fp);
	return;
}

//
// Open the TCP port on which the HTTP interface
// will be listening
//

int control_open_port(int port) {
	int sockfd;  
	struct sockaddr_in my_addr;
	int yes=1;


	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket error occured");
		exit(1);
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
		perror("setsockopt error occured");
		exit(1);
	}

	if(CONFIG_CONTROL_HTTP_IP == INADDR_NONE) {
		log_warn("Control thread got malformed IP, check config");
		return -1;
	}
	
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(port);
	my_addr.sin_addr.s_addr = CONFIG_CONTROL_HTTP_IP;
	memset(&(my_addr.sin_zero), '\0', 8);


	if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) == -1) {
		perror("could not bind");
		exit(1);
	}

	if (listen(sockfd, BACKLOG) == -1) {
		perror("listen on port failed");
		exit(1);
	}

	if(CONFIG_CONTROL_HTTP_IP == INADDR_ANY) {
		log_info("Control thread accepting on: http://0.0.0.0:%d",port);
	} else {
		log_info("Control thread accepting on: http://%s:%d",inet_ntoa(my_addr.sin_addr),port);
	}

	return sockfd;
}

//
// Reload signatures
//

int reloadSignatures() {

	log_info("Signature reload: starts now");
	log_info("Signature reload: stopping analyzer thread");
	loop_analyzer=0;

	// Stop the sniffer thread 
	// Todo, check return value (via arg 2)
	pthread_join(t_analyzer,NULL);
	log_info("Signature reload: free'ing signatures");

	// Free the signatures
	freeSignatures();

	// Load the new signatures
	log_info("Signature reload: loading signatures");
	load_signatures(CONFIG_SIGFILE);

	// Start new sniffer thead
	log_info("Signature reload: starting sniffer thread");
	loop_analyzer=1;
	pthread_create(&t_analyzer,NULL,(void*)pcap_analyzer,NULL);

	return 1;
}

//
// The heart of the control thead. Currently responsible for serving HTTP
// requests and executing the timer_run function. Perhaps this needs to
// be split in the future..
//

void control_loop() {

	struct sockaddr_in gaddr;
	struct timeval seltimeout;
	socklen_t sin_size = sizeof(struct sockaddr_in);
	int count,sockfd,clientfd;
	fd_set sockset;

	if(CONFIG_CONTROL_HTTP_ENABLE == 1) {
		// Start listening on the port
		if((sockfd = control_open_port(CONFIG_CONTROL_HTTP_PORT)) == -1) {
			CONFIG_CONTROL_HTTP_ENABLE = 0;
		}
		// Select timeout is 1 sec
		seltimeout.tv_sec  = 1;
		seltimeout.tv_usec = 0;
	}

	while(loop_control) {  

		// Check if there is someone on the end of the line.. then
		// execute the timers and sleep for a while to avoid CPU hogging

		if(CONFIG_CONTROL_HTTP_ENABLE == 1) {
			FD_ZERO(&sockset);
			FD_SET(sockfd,&sockset);

			if(select(sockfd + 1, &sockset, NULL, NULL, &seltimeout) == -1) {
				continue;
			}

			if(FD_ISSET(sockfd, &sockset) == 1 && loop_control) {
				
				// Someone knocked at the door
				if ((clientfd = accept(sockfd, (struct sockaddr *)&gaddr, &sin_size)) == -1) {
					perror("accept");
					continue;
				}

				log_info("Control thread: got connection from %s",inet_ntoa(gaddr.sin_addr));
				handle_connection(clientfd);
				close(clientfd);
			}
		} else {

			// We got the time.. todo: perhaps try sleeping a bit shorter
			sleep(1);
		}

		// Run the timers, if any 
		timer_run();

		// Pop all messages
		count = 0;
		while(pop_message() != 0 && count++ != 100) {
			// do nothin..
		}
	}

	close(sockfd);
}

int handle_connection(int clientfd) {

	char readbuf[BUF_SIZE];
	int readbytes = 0;
	FILE *fsock;

	fsock = fdopen(clientfd,"w");

	bzero(readbuf,BUF_SIZE);
	readbytes = read(clientfd,readbuf,BUF_SIZE -1);
	
	if(readbytes > 0) {

		if(check_http_auth(readbuf,readbytes,fsock) == 1) {
			fprintf(fsock,"HTTP/1.0 401 Unauthorized\r\n");
			fprintf(fsock,"WWW-Authenticate: Basic realm=\"FreeIPS\"\r\n");
			fprintf(fsock,"Connection: close\r\n\r\n");
			fflush(fsock);
			fclose(fsock);
			close(clientfd);

			log_info("Control thread: HTTP authentication failed!");
			
			return 0;
		}

		switch(extract_cmd(readbuf)) {
			case '0':
				send_http_response(clientfd,HTTP_TYPE_HTML,"");
				write_file_to_fd(fsock,CONFIG_CONTROL_HTTP_HEADER);
				fprintf(fsock, "Please chose one of the above options\n");
				write_file_to_fd(fsock,CONFIG_CONTROL_HTTP_FOOTER);
				break;
			case '1':
				send_http_response(clientfd,HTTP_TYPE_HTML,"");
				write_file_to_fd(fsock,CONFIG_CONTROL_HTTP_HEADER);
				fprintf(fsock, "<pre>\n");
				dump_stats(fsock);
				fprintf(fsock, "</pre>\n");
				write_file_to_fd(fsock,CONFIG_CONTROL_HTTP_FOOTER);
				break;
			case '2':
				send_http_response(clientfd,HTTP_TYPE_HTML,"");
				write_file_to_fd(fsock,CONFIG_CONTROL_HTTP_HEADER);
				fprintf(fsock, "<pre>\n");
				tcp_dump_sessions(fsock);
				fprintf(fsock, "</pre>\n");
				write_file_to_fd(fsock,CONFIG_CONTROL_HTTP_FOOTER);
				fflush(fsock);
				break;
			case '3':
				reloadSignatures();
				send_http_response(clientfd,HTTP_TYPE_HTML,"");
				write_file_to_fd(fsock,CONFIG_CONTROL_HTTP_HEADER);
				fprintf(fsock, "Reloading!!!\n");
				write_file_to_fd(fsock,CONFIG_CONTROL_HTTP_FOOTER);
				break;
			case '4':
				send_http_response(clientfd,HTTP_TYPE_HTML,"");
				write_file_to_fd(fsock,CONFIG_CONTROL_HTTP_HEADER);
				if(is_file(logoutputs[LOG_TYPE_ALERT].name)) {
					fprintf(fsock, "<pre>\n");
					write_file_to_fd(fsock,logoutputs[LOG_TYPE_ALERT].name);
					fprintf(fsock, "</pre>\n");
				} else {
					fprintf(fsock, "Nothing to report (yet)\n");
				}
				write_file_to_fd(fsock,CONFIG_CONTROL_HTTP_FOOTER);
				break;
		}
	}
				
	fclose(fsock);
	close(clientfd);

	return 0;
}

