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

struct linked_list *trafficlist;
int loop_control  = 1;
int loop_sniffer  = 1;
int loop_analyzer = 1;
int loop_main	  = 1;
int mode_offline  = 0;
extern int sigcount;

struct timeval startuptime;
pcap_t *handle = NULL;
pthread_t t_listener;
pthread_t t_analyzer;
pthread_t t_control;

int main(int argc, char **argv)  {

        int arg,ret;
	char *configfile;
	char pcapfile[256];

	// Load default config
	init_config();

        // Set the signal handlers
        signal(SIGHUP, sighup_handler);
        signal(SIGINT, sigquit_handler);
        signal(SIGQUIT,sigquit_handler);


        // Parse command-line options
        while ((arg = getopt(argc, argv, "IP:i:c:f:DqvdTsr:l:u:S:")) != -1){
                switch (arg){
                        case 'f':
                                strncpy(CONFIG_PCAP_FILTER,optarg,CONFIG_MAX_CHAR);
                                break;
			case 'r':
				strncpy(pcapfile,optarg,256);
				mode_offline=1;
				break;
			case 'c':
				configfile = optarg;
				read_config(configfile);
				//dump_config();
				break;
                        case 'i':
				// Start the pcap thread
                                strncpy(CONFIG_PCAP_DEV,optarg,CONFIG_MAX_CHAR);
                                break;
                        case 'P':
				CONFIG_DIVERT_PORT=atoi(optarg);
				break;
			case 'I':
				CONFIG_DIVERT_ENABLE=1;
                                break;
                        case 'q':
                                CONFIG_LOG_STDOUT = 0;
                                break;
                        case 'u':
				strncpy(CONFIG_USER,optarg,CONFIG_MAX_CHAR);
                                break;
                        case 'l':
                                strncpy(CONFIG_LOGDIR,optarg,CONFIG_MAX_CHAR);
				if(strlen(CONFIG_LOGDIR) > 64) {
					fatal_error("Log directory is too long!");
				}
				if (access(CONFIG_LOGDIR, F_OK) == -1){
					fatal_error("Log directory does not exist");
				}
                                break;
                        case 's':
                                CONFIG_LOG_SYSLOG = 1;
                                break;
			case 'S':
                                strncpy(CONFIG_SIGFILE,optarg,CONFIG_MAX_CHAR);
				break;
			case 'T':
				CONFIG_TCP_STRICT = 0;
				break;
                        case 'v':
                                CONFIG_LOG_VERBOSE++;
                                break;
			case 'd':
				CONFIG_SHOW_TRAFFIC = 1;
				break;
                        case 'D':
				fork_to_background(); 
                                break;
                        default:
				usage();
				exit(1);
                                break;
                }
        }

	// Initialize the stats structure and the streams
	stats_init();

        // Create the list, this is to store the IP packets in which can then
        // be read by another thread. TODO: add maximum list size
        trafficlist = getNewList();
	setListSize(MAX_LIST_SIZE,trafficlist);

        // Register the destructor
        registerListDestructor(destructor_callback,trafficlist);
        registerListIterator(traffic_analyzer,trafficlist);

	// Create the control thread first for message logging
        pthread_create(&t_control,NULL,(void*)control_loop,NULL);

	//Initialize the detection hooks
	detect_hook_init();
	tcp_stream_init();

	//Initialize the timers
	timer_init();
	timer_register_function(CONFIG_TIMER_STATS,"Stats printer",stats_show_cnt_line,NULL);
	timer_register_function(CONFIG_TIMER_TCP_CLEANER,"TCP session cleaner", tcp_clean_sessions,NULL);
	timer_register_function(CONFIG_TIMER_IPFRAG_CLEANER,"IP fragment cleaner", ip_frag_cleaner,NULL);
	timer_register_function(CONFIG_TIMER_CLEANUPPBUFFER,"Packet list cleaner", cleanListBacklog, (void*)trafficlist);

	//Load the signatures
	if(load_signatures(CONFIG_SIGFILE) == -1){
		usage();
		exit(1);
	}

	log_info("Loaded signature count: %d", sigcount);


	// Check if root privileges are required
	if(mode_offline == 0 && getuid() != 0) {
		fprintf(stderr, "Root privileges are required, unless you specify a\n");
		fprintf(stderr, "pcap file with the '-r' option..\n");
		exit(1);
	}

	if(CONFIG_DIVERT_ENABLE) {
		log_info("Opening DIVERT socket port: %d\n",CONFIG_DIVERT_PORT);
		divert_open_socket(CONFIG_DIVERT_PORT);

		// Start the divert_listen loop
		pthread_create(&t_listener,NULL,(void*)divert_listen_loop,handle);
	} else if(mode_offline != 1) {

		// If no device was specified AND not configured then the only
		// option is to pick one using the cap library (not recommended)
		if(*CONFIG_PCAP_DEV == '0') {
			if(pcap_return_device() != NULL) {
				log_info("Picking random interface (overrule -i)");
				strncpy(CONFIG_PCAP_DEV,pcap_return_device(),CONFIG_MAX_CHAR);
			} else {
					usage();
					exit(1);
			}
		}

		// Start the sniffer thread
		handle = pcap_open_device(CONFIG_PCAP_DEV,CONFIG_PCAP_FILTER);
		pthread_create(&t_listener,NULL,(void*)pcap_listen_loop,handle);
	} else {

		// Open the file
		handle = pcap_open_file(pcapfile,CONFIG_PCAP_FILTER);
		pthread_create(&t_listener,NULL,(void*)pcap_listen_loop,handle);
	}

	// Chroot if needed
	if(CONFIG_CHROOT_ENABLE == 1) {
		if((ret = chroot(CONFIG_CHROOT_DIR)) != 0) {
			fatal_error("Chroot to \"%s\" failed: %s !",CONFIG_CHROOT_DIR, strerror(errno));
		} else {
			log_info("Chroot to directory: \"%s\" done",CONFIG_CHROOT_DIR);
		}
	}

	// Drop privileges if needed
	if(*CONFIG_USER != '0' && drop_privileges(CONFIG_USER) != 0) {
		fatal_error("Unable to drop privileges, quitting for security reasons",CONFIG_USER);
	}

	// Set the time
	gettimeofday(&startuptime,NULL);
        pthread_create(&t_analyzer,NULL,(void*)pcap_analyzer,NULL);
        pthread_join(t_listener,NULL);

	if(mode_offline == 1) {
		sleep(1);
		loop_analyzer = 0;
		pthread_join(t_analyzer, NULL);
	}

        // Free the list.
        freeList(trafficlist,1);

	// Control thread
	loop_control = 0;
	pthread_join(t_control, NULL);

	// And bail out
	dump_stats(stdout);
        return 0;
}


int destructor_callback (void *data,struct list_entry *entry) {
	DEBUG(stdout,"In destructor\n");
	return 0;
}

