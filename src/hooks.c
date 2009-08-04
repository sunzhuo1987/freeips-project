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

DetectHook *DetectHooks[DETECT_HOOK_MAX_CNT];

//
// Initialize the hooks array with NULL's in order to be
// able checks what pointers were added
//

void detect_hook_init() {
	int i;
	for(i=0;i<DETECT_HOOK_MAX_CNT;i++) {
		DetectHooks[i] = NULL;
	}

	//
	// Register the detection hooks. They can be linked to signatures
	// and used in the detection engine..
	//
	
	detect_hook_register("pcre"      ,0, HOOK_PRIO_LOW,    hook_pcre,hook_pcre_options);
	detect_hook_register("flow"      ,0, HOOK_PRIO_NORMAL, hook_flow,hook_flow_options);
	detect_hook_register("content"   ,0, HOOK_PRIO_LOW,    hook_content,hook_content_options);
	detect_hook_register("ip_id"     ,0, HOOK_PRIO_HIGH,   hook_ip_id,hook_ip_id_options);
	detect_hook_register("ip_ttl"    ,0, HOOK_PRIO_HIGH,   hook_ip_ttl,hook_ip_ttl_options);
	detect_hook_register("ip_tos"    ,0, HOOK_PRIO_HIGH,   hook_ip_tos,hook_ip_tos_options);
	detect_hook_register("p0f"       ,0, HOOK_PRIO_LOW,    hook_p0f,hook_p0f_options);
	detect_hook_register("dsize"     ,0, HOOK_PRIO_HIGH,   hook_dsize,hook_dsize_options);
	detect_hook_register("socom"     ,0, HOOK_PRIO_LOW,    hook_socom,hook_socom_options);
	detect_hook_register("flags"     ,0, HOOK_PRIO_HIGH,   hook_tcp_flags,hook_tcp_flags_options);
	detect_hook_register("uricontent",0, HOOK_PRIO_LOW,    hook_uricontent,hook_uricontent_options);
	detect_hook_register("latency"   ,0, HOOK_PRIO_LOW,    hook_latency,hook_latency_options);
	detect_hook_register("seq"       ,0, HOOK_PRIO_HIGH,   hook_tcp_seq,hook_tcp_seq_options);
	detect_hook_register("ack"       ,0, HOOK_PRIO_HIGH,   hook_tcp_ack,hook_tcp_ack_options);
	detect_hook_register("itype"     ,0, HOOK_PRIO_HIGH,   hook_icmp_itype,hook_icmp_itype_options);
	detect_hook_register("icode"     ,0, HOOK_PRIO_HIGH,   hook_icmp_icode,hook_icmp_icode_options);

}

//
// Sort the hooks of a signature using the priority in
// order to get a better performance 
//

void sort_hooks(struct signature *sig) {

	int count;
	DetectHook *tmphook;

	// First copy the pointers
        for(count=0;count < (DETECT_HOOK_MAX_CNT + 1);count++) {

		if(sig->DetectHooks[count] == NULL || sig->DetectHooks[count + 1] == NULL)
			break;

		tmphook = sig->DetectHooks[count];

		if(sig->DetectHooks[count]->prio < sig->DetectHooks[count + 1]->prio) {
			sig->DetectHooks[count] = sig->DetectHooks[count + 1];
			sig->DetectHooks[count + 1] = tmphook;
		}

        }
}

//
// Simple function to add a hook to the array
//

DetectHook * detect_hook_register(char *name, int options, int priority, int(*hook)(struct signature *sig,struct traffic *traffic),
							   int (*hook_parse_option)(char *key, char *val, struct signature *sig)) {

	int count;
	DetectHook *newhook;

	if((newhook = (DetectHook *)allocMem(sizeof(DetectHook))) == NULL) {
		fatal_error("Unable to alloc memory for detect hook: %s",name);
	}

	// Find an empty spot
	for(count=0; count<DETECT_HOOK_MAX_CNT;count++) {
		if(DetectHooks[count] == NULL){
			DetectHooks[count] = newhook;
			break;
		}
	}

	if(count == DETECT_HOOK_MAX_CNT) {
		fatal_error("Can't register DetectHook: %s (enlarge DETECT_HOOK_MAX_CNT)",name);
	}

	// Set the name
	strncpy(newhook->name,name,DETECT_HOOK_NAME_SIZE);

	// Set the hook
	newhook->hook = hook;
	newhook->prio = priority;
	newhook->hook_parse_option = hook_parse_option;

	log_info("Linked detection hook %d: %s",count,name);

	return newhook;
}

//
// Get a detect hook. It can then be linked to a signature.
//

DetectHook * detect_hook_get(char *name) {

	int count;
	for(count = 0;count < DETECT_HOOK_MAX_CNT;count++) {
		if(DetectHooks[count] == NULL)
			break;

		//printf("Comparing %s --> %s\n",DetectHooks[count]->name,name);
		if(strcmp(DetectHooks[count]->name,name) == 0)
			return DetectHooks[count];
	}

	return NULL;
}

//
// Register a hook to a signature
//

DetectHook * detect_hook_link(struct signature *sig, char *name) {

	int count;
	DetectHook *myhook = NULL;

	if((myhook = detect_hook_get(name)) == NULL) {
		fatal_error("Can't find hook: %s",name);
	}

	for(count=0;count < DETECT_HOOK_MAX_CNT;count++) {
		if(sig->DetectHooks[count] == NULL) 		
			break;

		if(strcmp(sig->DetectHooks[count]->name,name) == 0)
			return myhook;

	}

	// Now link it
	sig->DetectHooks[count] = myhook;

	return myhook;
}






