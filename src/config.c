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
// THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRFreeIPSES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRFreeIPSES OF MERCHANTABILITY
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

int init_config() {

	CONFIG_LOG_SYSLOG  =0;
	CONFIG_LOG_PACKET  =0;
	CONFIG_LOG_VERBOSE =0;
	CONFIG_SHOW_TRAFFIC=0;
	CONFIG_LOG_STDOUT  =1;

	// with the below option we decide whether to
	// load signatures that have unload options or now
	// by default: do not load them 
	CONFIG_SIG_STRICT_LOAD=1;

	// Security
	*CONFIG_CHROOT_DIR     = '0';
	CONFIG_CHROOT_ENABLE   = 0;
	CONFIG_DROP_PRIVILEGES = 1;
	strncpy(CONFIG_USER,"nobody", CONFIG_MAX_CHAR);

	strncpy(CONFIG_SIGFILE,"/usr/local/share/FreeIPS/config/signatures/", CONFIG_MAX_CHAR);
	strncpy(CONFIG_LOGDIR,"/usr/local/share/FreeIPS/logdir/",CONFIG_MAX_CHAR);
	strncpy(CONFIG_PCAP_FILTER,"ip",CONFIG_MAX_CHAR);
	strncpy(CONFIG_PCAP_DEV,"0",CONFIG_MAX_CHAR);

	// Divert related
	CONFIG_TCP_STRICT   =1;
	CONFIG_DIVERT_ENABLE=0;
	CONFIG_DIVERT_PORT=2222;

	// Timer stuff
	CONFIG_TIMER_STATS=600;       
	CONFIG_TIMER_TCP_CLEANER=3600; 
	CONFIG_TIMER_IPFRAG_CLEANER=10; 

	// Ringbuffer
	CONFIG_RINGBUFFER_SIZE=500000;
	
	// Control thread
	CONFIG_CONTROL_HTTP_PORT   = 3491;
	CONFIG_CONTROL_HTTP_ENABLE = 1;
	CONFIG_CONTROL_HTTP_IP     = inet_addr("127.0.0.1");
	strncpy(CONFIG_CONTROL_HTTP_FOOTER,"support/html/footer.html",CONFIG_MAX_CHAR);
	strncpy(CONFIG_CONTROL_HTTP_HEADER,"support/html/header.html",CONFIG_MAX_CHAR);
	strncpy(CONFIG_CONTROL_HTTP_USER,"user",CONFIG_MAX_CHAR);
	strncpy(CONFIG_CONTROL_HTTP_PASS,"letmein",CONFIG_MAX_CHAR);
	snprintf(CONFIG_CONTROL_HTTP_AUTH_CLEAR,CONFIG_MAX_CHAR,"%s:%s",CONFIG_CONTROL_HTTP_USER,CONFIG_CONTROL_HTTP_PASS);
        base64_encode(CONFIG_CONTROL_HTTP_AUTH_CLEAR,CONFIG_CONTROL_HTTP_AUTH);

	// Initialize the logfiles
	logoutputs_init();


	return 0;
}

void dump_config() {

	printf("<?xml version=\"1.0\"?>\n");
	printf("<config>\n");
	printf("  <general>\n");
	printf("    <logdir>%s</logdir>\n",CONFIG_LOGDIR);
	printf("    <sigfile>%s</sigfile>\n",CONFIG_SIGFILE);
	printf("    <pcapfilter>%s</pcapfilter>\n",CONFIG_PCAP_FILTER);
	printf("    <pcapdevice>%s</pcapdevice>\n",CONFIG_PCAP_DEV);
	printf("    <user></user>\n");
	printf("    <tcpstrict>%d</tcpstrict>\n",CONFIG_TCP_STRICT);
	printf("    <inline>%d</inline>\n",CONFIG_DIVERT_ENABLE);
	printf("    <inlineport>%d</inlineport>\n",CONFIG_DIVERT_PORT);
	printf("    <controlport>%d</controlport>\n",CONFIG_CONTROL_HTTP_PORT);
	printf("  </general>\n");
	printf("  <logging>\n");
	printf("   <verbosity>%d</verbosity>\n",CONFIG_LOG_VERBOSE);
	printf("   <dumppacket>%d</dumppacket>\n",CONFIG_LOG_PACKET);
	printf("   <syslog>%d</syslog>\n",CONFIG_LOG_SYSLOG);
	printf("   <stdout>%d</stdout>\n",CONFIG_LOG_STDOUT);
	printf("   <showtraffic>%d</showtraffic>\n",CONFIG_SHOW_TRAFFIC);
	printf("  </logging>\n");
	printf("</config>\n");

}

void parse_general (xmlDocPtr doc, xmlNodePtr cur) {

	xmlChar *key, *attr;
	xmlNodePtr tmp;
	int number;

	cur = cur->xmlChildrenNode;
	while (cur != NULL) {

		if ((!xmlStrcmp(cur->name, (const xmlChar *)"sigfile"))) {
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			strncpy(CONFIG_SIGFILE,(char *)key,CONFIG_MAX_CHAR);
			xmlFree(key);
		}
                if ((!xmlStrcmp(cur->name, (const xmlChar *)"ringbuffer"))) {
                        key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
                        number = atoi((char *)key);
                        if(number > 1) {
                                CONFIG_RINGBUFFER_SIZE = number;
                        } else {
                                log_warn("Configuration option for \"ringbuffer\" should greater then 1");
                        }
                        xmlFree(key);
                }

		if ((!xmlStrcmp(cur->name, (const xmlChar *)"sigstrict"))) {
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			number = atoi((char *)key);
			if(number == 1 || number == 2) {
				CONFIG_SIG_STRICT_LOAD = number;
			} else {
				log_warn("Configuration option for \"sigstrict\" should be 1 or 0");
			}
			xmlFree(key);
		}
		if ((!xmlStrcmp(cur->name, (const xmlChar *)"pcapfilter"))) {
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			strncpy(CONFIG_PCAP_FILTER,(char *)key,CONFIG_MAX_CHAR);
			xmlFree(key);
		}
		if ((!xmlStrcmp(cur->name, (const xmlChar *)"pcapdevice"))) {
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			strncpy(CONFIG_PCAP_DEV,(char *)key,CONFIG_MAX_CHAR);
			xmlFree(key);
		}
		if ((!xmlStrcmp(cur->name, (const xmlChar *)"security"))) {
			// Check for nested XML tag
			tmp = cur->xmlChildrenNode;
			while (tmp != NULL) {

				if ((!xmlStrcmp(tmp->name, (const xmlChar *)"run_as_user"))) {
					attr = xmlGetProp(tmp,(const xmlChar *)"enable");
					if(attr != NULL) {
						number = atoi((char *)attr);
						if(number == 0 || number == 1) {
							CONFIG_DROP_PRIVILEGES=number;
							key = xmlNodeListGetString(doc, tmp->xmlChildrenNode, 1);
							strncpy(CONFIG_USER,(char *)key,CONFIG_MAX_CHAR);
							xmlFree(key);
						} else {
							log_warn("Configuration option for \"run_as_user\" \"enable\" should be 1 or 0");
						}
						xmlFree(attr);
					}
				}
				if ((!xmlStrcmp(tmp->name, (const xmlChar *)"chroot_dir"))) {
					attr = xmlGetProp(tmp,(const xmlChar *)"enable");
					if(attr != NULL) {
						number = atoi((char *)attr);
						if(number == 0 || number == 1) {
							CONFIG_CHROOT_ENABLE=number;
							key = xmlNodeListGetString(doc, tmp->xmlChildrenNode, 1);
							strncpy(CONFIG_CHROOT_DIR,(char *)key,CONFIG_MAX_CHAR);
							xmlFree(key);
						} else {
							log_warn("Configuration option for \"chroot_dir\" \"enable\" should be 1 or 0");
						}
						xmlFree(attr);
					}
				}

				tmp=tmp->next;
			}
		}

		// CONFIG_TCP_STRICT
		if ((!xmlStrcmp(cur->name, (const xmlChar *)"tcpstrict"))) {
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			if(*key == '0' || *key == '1') {
				CONFIG_TCP_STRICT= atoi((char *)key);
			} else {
				log_warn("Configuration option for \"tcpstrict\" should be 1 or 0");
			} 
			xmlFree(key);
		}

		if ((!xmlStrcmp(cur->name, (const xmlChar *)"inline"))) {
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			if(*key == '0' || *key == '1') {
				CONFIG_DIVERT_ENABLE= atoi((char *)key);
			} else {
				log_warn("Configuration option for \"inline\" should be 1 or 0");
			} 
			xmlFree(key);
		}
		if ((!xmlStrcmp(cur->name, (const xmlChar *)"inlineport"))) {
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			if(*key > '0') {
				CONFIG_DIVERT_PORT=atoi((char *)key);
			} else {
				log_warn("Configuration option for \"inlineport\" should be 1 <> 65535 0");
			} 
			xmlFree(key);
		}
		cur = cur->next;
	}
    return;
}
void parse_control (xmlDocPtr doc, xmlNodePtr cur) {
	xmlChar *attr,*key;
	xmlNodePtr tmp;
	int number;

	cur = cur->xmlChildrenNode;
	while (cur != NULL) {
		if ((!xmlStrcmp(cur->name, (const xmlChar *)"http"))) {
			attr = xmlGetProp(cur,(const xmlChar *)"enable");
			if(attr != NULL) {
				number = atoi((char *)attr);
				if(number == 0 || number == 1) {
					CONFIG_CONTROL_HTTP_ENABLE=number;
				} else {
					log_warn("Configuration option for \"http\" enable should be 1 or 0");
				}
				xmlFree(attr);
			}
			attr = xmlGetProp(cur, (const xmlChar *)"port");
			if(attr != NULL) {
				number = atoi((char *)attr);
				if(number > 1 || number < 65535) {
					CONFIG_CONTROL_HTTP_PORT=number;
				} else {
					log_warn("Configuration option for \"http\" port unrealistic");
				}
				xmlFree(attr);
			}

			attr = xmlGetProp(cur, (const xmlChar *)"ip");
			if(attr != NULL) {
				CONFIG_CONTROL_HTTP_IP = inet_addr((char *)attr);
				xmlFree(attr);
			}

			tmp = cur->xmlChildrenNode;
			number = 0;
			while (tmp != NULL) {
                                if ((!xmlStrcmp(tmp->name, (const xmlChar *)"user"))) {
                                        key = xmlNodeListGetString(doc, tmp->xmlChildrenNode, 1);
					strncpy(CONFIG_CONTROL_HTTP_USER,(char *)key,CONFIG_MAX_CHAR);
                                        xmlFree(key);
                                }
                                if ((!xmlStrcmp(tmp->name, (const xmlChar *)"pass"))) {
                                        key = xmlNodeListGetString(doc, tmp->xmlChildrenNode, 1);
					strncpy(CONFIG_CONTROL_HTTP_PASS,(char *)key,CONFIG_MAX_CHAR);
                                        xmlFree(key);
                                }

				snprintf(CONFIG_CONTROL_HTTP_AUTH_CLEAR,CONFIG_MAX_CHAR,"%s:%s",CONFIG_CONTROL_HTTP_USER,CONFIG_CONTROL_HTTP_PASS);
				base64_encode(CONFIG_CONTROL_HTTP_AUTH_CLEAR,CONFIG_CONTROL_HTTP_AUTH);
				tmp = tmp->next;
			}
		}

		if ((!xmlStrcmp(cur->name, (const xmlChar *)"timer"))) {

			// Check for nested XML tag
			tmp = cur->xmlChildrenNode;
			while (tmp != NULL) {
				if ((!xmlStrcmp(tmp->name, (const xmlChar *)"print_stats"))) {
					key = xmlNodeListGetString(doc, tmp->xmlChildrenNode, 1);
					number = atoi((char *)key);
					if(number > 1 || number < 65535) {
						CONFIG_TIMER_STATS=number;
					} else {
						log_warn("Configuration option for \"print_stats\" is not sane");
					}
					xmlFree(key);
				}
				if ((!xmlStrcmp(tmp->name, (const xmlChar *)"cleanup_tcp"))) {
					key = xmlNodeListGetString(doc, tmp->xmlChildrenNode, 1);
					number = atoi((char *)key);
					if(number > 1 || number < 65535) {
						CONFIG_TIMER_TCP_CLEANER=number;
					} else {
						log_warn("Configuration option for \"cleanup_tcp\" is not sane");
					}
					xmlFree(key);
				}

				if ((!xmlStrcmp(tmp->name, (const xmlChar *)"cleanup_ipfrags"))) {
					key = xmlNodeListGetString(doc, tmp->xmlChildrenNode, 1);
					number = atoi((char *)key);
					if(number > 1 || number < 65535) {
						CONFIG_TIMER_IPFRAG_CLEANER=number;
					} else {
						log_warn("Configuration option for \"cleanup_ipfrags\" is not sane");
					}
					xmlFree(key);
				}

				tmp = tmp->next;
			}
		}

		if ((!xmlStrcmp(cur->name, (const xmlChar *)"syslog"))) {
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);


		}

		if ((!xmlStrcmp(cur->name, (const xmlChar *)"html_footer"))) {
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			strncpy(CONFIG_CONTROL_HTTP_FOOTER,(char *)key,CONFIG_MAX_CHAR);
			xmlFree(key);
		}
		if ((!xmlStrcmp(cur->name, (const xmlChar *)"html_header"))) {
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			strncpy(CONFIG_CONTROL_HTTP_HEADER,(char *)key,CONFIG_MAX_CHAR);
			xmlFree(key);
		}
		cur = cur->next;
	}
}



void parse_logging (xmlDocPtr doc, xmlNodePtr cur) {

	xmlChar *key, *attr;
	xmlNodePtr tmp;
	int number;
	int loglevel,enable;

	cur = cur->xmlChildrenNode;
	while (cur != NULL) {
		if ((!xmlStrcmp(cur->name, (const xmlChar *)"verbosity"))) {
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
                        if(*key >= '0' && *key <= '9') {
                                CONFIG_LOG_VERBOSE=atoi((char *)key);
                        } else {
                                log_warn("Configuration option for \"verbosity\" should be 1 <> 9");
                        }

			xmlFree(key);
		}
		if ((!xmlStrcmp(cur->name, (const xmlChar *)"dump_packet"))) {

                        attr = xmlGetProp(cur,(const xmlChar *)"enable");
                        if(attr != NULL) {
                                number = atoi((char *)attr);
                                if(number == 0 || number == 1) {
                                        CONFIG_LOG_PACKET=number;
                                } else {
					log_warn("Configuration option for \"dumppacket\" should be 1 or 0");
                                }
				xmlFree(attr);
                        }

			// Check for nested XML tag
			tmp = cur->xmlChildrenNode;
			while (tmp != NULL) {
				if ((!xmlStrcmp(tmp->name, (const xmlChar *)"output_dir"))) {
					key = xmlNodeListGetString(doc, tmp->xmlChildrenNode, 1);
					strncpy(CONFIG_LOGDIR,(char *)key,CONFIG_MAX_CHAR);
					xmlFree(key);
				}
				tmp = tmp->next;
			}
			

		}

                if ((!xmlStrcmp(cur->name, (const xmlChar *)"logfile"))) {

			loglevel=6;
			enable=0;
			attr = xmlGetProp(cur,(const xmlChar *)"level");
			if(attr != NULL) {

				if(strncmp((char *)attr,"alert",5) == 0) {
					loglevel=LOG_TYPE_ALERT;
				} else if(strncmp((char *)attr,"info",5) == 0) {
					loglevel=LOG_TYPE_INFO;
				} else if(strncmp((char *)attr,"error",5) == 0) {
					loglevel=LOG_TYPE_ERROR;
				} else if(strncmp((char *)attr,"warn",4) == 0) {
					loglevel=LOG_TYPE_WARN;
				} else if(strncmp((char *)attr,"fatal",5) == 0) {
					loglevel=LOG_TYPE_WARN;
				} else if(strncmp((char *)attr,"verbose",5) == 0) {
					loglevel=LOG_TYPE_VERBOSE;
				} else if(strncmp((char *)attr,"all",3) == 0) {
					loglevel=LOG_TYPE_ALL;
				} 
                                xmlFree(attr);
			} 
                         
                        attr = xmlGetProp(cur,(const xmlChar *)"enable");
                        if(attr != NULL) {
                                enable = atoi((char *)attr);
                                xmlFree(attr);
                        }
                         
                        // Check for nested XML tag
                        tmp = cur->xmlChildrenNode;
                        while (tmp != NULL) {
                                if ((!xmlStrcmp(tmp->name, (const xmlChar *)"filename"))) {
                                        key = xmlNodeListGetString(doc, tmp->xmlChildrenNode, 1);

					if(loglevel != LOG_TYPE_ALL && loglevel < LOG_FILE_NAME_CNT && loglevel > 0) {
						logoutputs[loglevel].enable = enable;
						strncpy(logoutputs[loglevel].name,(char *)key,CONFIG_MAX_CHAR);
					} else {

						// All levels to this file
						for(number=0;number<LOG_FILE_NAME_CNT;number++) {
							// If "other" is used then log everything *else*
							// into this file.
							if(loglevel == LOG_TYPE_OTHER) {
								if(logoutputs[loglevel].name != NULL);
									continue;
							}
							logoutputs[number].enable = enable;
							strncpy(logoutputs[number].name,(char *)key,CONFIG_MAX_CHAR);
						}
					}

                                        xmlFree(key);
                                }
                                tmp = tmp->next;
                        }

                }



		if ((!xmlStrcmp(cur->name, (const xmlChar *)"syslog"))) {
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
                        if(*key == '0' || *key == '1') {
                                CONFIG_LOG_SYSLOG=atoi((char *)key);
                        } else {
                                log_warn("Configuration option for \"syslog\" should be 1 or 0");
                        }

			xmlFree(key);
		}
		if ((!xmlStrcmp(cur->name, (const xmlChar *)"stdout"))) {
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
                        if(*key == '0' || *key == '1') {
                                CONFIG_LOG_STDOUT=atoi((char *)key);
                        } else {
                                log_warn("Configuration option for \"stdout\" should be 1 or 0");
                        }
			xmlFree(key);
		}
		if ((!xmlStrcmp(cur->name, (const xmlChar *)"showtraffic"))) {
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
                        if(*key == '0' || *key == '1') {
                                CONFIG_SHOW_TRAFFIC=atoi((char *)key);
                        } else {
                                log_warn("Configuration option for \"showtraffic\" should be 1 or 0");
                        }

			xmlFree(key);
		}
            cur = cur->next;
        }
    return;
}

// Todo: small update to read also from HTTP interface in order to
// allow remote config push
void read_config(char *docname) {

	xmlDocPtr doc;
	xmlNodePtr cur;

	doc = xmlParseFile(docname);
	
	if (doc == NULL ) {
		fatal_error("Configuration was not parsed successfully.");
		return;
	}
	
	cur = xmlDocGetRootElement(doc);
	
	if (cur == NULL) {
		fatal_error("No content found in XML");
		xmlFreeDoc(doc);
		return;
	}
	
	if (xmlStrcmp(cur->name, (const xmlChar *) "config")) {
		fatal_error("Config is not formatted correct: root node != config");
		xmlFreeDoc(doc);
		return;
	}
	
	cur = cur->xmlChildrenNode;
	while (cur != NULL) {
		if ((!xmlStrcmp(cur->name, (const xmlChar *)"general"))){
			parse_general (doc, cur);
		}
                if ((!xmlStrcmp(cur->name, (const xmlChar *)"logging"))){
                        parse_logging (doc, cur);
                }
                if ((!xmlStrcmp(cur->name, (const xmlChar *)"control_thread"))){
                        parse_control (doc, cur);
                }
                cur = cur->next;
	}
	xmlFreeDoc(doc);
	
	return;
}
