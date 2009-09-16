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

// 0 is success

int hook_byte_test(struct signature *sig,struct traffic *traffic) {

	int index,i;
	struct byte_test *bptr;
	char digitstr[BYTE_MAX_DIGIT];
	char *pptr;
	long digit;

	pptr = (char *)traffic->payload;

        for(index=0;index<SIG_MAX_BYTETEST;index++) {
                if(sig->byte_test[index] != NULL) {
			bptr = sig->byte_test[index];

			switch(bptr->number_type) {
				case BYTE_TYPE_HEX:
					// Todo
					break;

				case BYTE_TYPE_DEC:
					
					for(i=0;i<BYTE_MAX_DIGIT && i < bptr->bytes_to_convert;i++) {
						digitstr[i] = pptr[i];
					}

					digitstr[i] = '\0';
					digit = atoi(digitstr);
					return do_byte_test(bptr,traffic,digit);
					
					break;

				case BYTE_TYPE_OCT:
					// Todo
					break;

				default:
					printf("huh bptr->bytes_to_convert weird value\n");
					break;
			};

			
			// Do the test
                }
        }

	
	return 1;
}

int do_byte_test (struct byte_test *bptr, struct traffic *traffic, long digit) {

	//Todo: relative!

	switch(bptr->operator) {
		case BYTE_OPERATOR_LT:
			if(digit < bptr->value) 
				return 1;

			break;

		case BYTE_OPERATOR_GT:
			if(digit > bptr->value) 
				return 1;

			break;
		case BYTE_OPERATOR_EQ:
			if(digit == bptr->value) 
				return 1;

			break;
		case BYTE_OPERATOR_NOT:
			if(digit != bptr->value) 
				return 1;

			break;
		case BYTE_OPERATOR_AND:
			//todo;
			break;
		case BYTE_OPERATOR_OR:
			//todo;
			break;

	};

	return 0;
}


// 0 is success
// 1 is failure

int hook_byte_test_options(char *key, char *val, struct signature *sig) {

	
	char *tptr;
	int index;
	int count = 0;

        // Find a slot to put the content struct into
        for(index=0;index<SIG_MAX_BYTETEST;index++) {
                if(sig->byte_test[index] == NULL) {
                        break;
                }
        }

        // Create the byte_test struct
        sig->byte_test[index] = (struct byte_test*) allocMem(sizeof(struct byte_test));
        memset(sig->byte_test[index],0,sizeof(struct byte_test));

	sig->byte_test[index]->bytes_to_convert = -1;
	sig->byte_test[index]->operator    = -1;
	sig->byte_test[index]->value       = -1;
	sig->byte_test[index]->offset      = -1;
	sig->byte_test[index]->relative    = -1;
	sig->byte_test[index]->endian      = -1;
	sig->byte_test[index]->string      = -1;
	sig->byte_test[index]->number_type = BYTE_TYPE_DEC;

	if((tptr = strtok(val,",")) == NULL) {
		printf("Return by first strtoken\n");
		return 1;
	}

	sig->byte_test[index]->bytes_to_convert = atoi(tptr);

	// for now !!
	if(sig->byte_test[index]->bytes_to_convert > 1) {
		return 1;
	}

	while((tptr = strtok(NULL,",")) != NULL) {
		switch(++count) {
			case 1:

				//////////////////////
				// Check the operator
				//

				switch(tptr[0]) {
					case '<':
						sig->byte_test[index]->operator = BYTE_OPERATOR_LT;
						break;
					case '>':
						sig->byte_test[index]->operator = BYTE_OPERATOR_GT;
						break;
					case '=':
						sig->byte_test[index]->operator = BYTE_OPERATOR_EQ;
						break;
					case '!':
						sig->byte_test[index]->operator = BYTE_OPERATOR_NOT;
						break;
					case '&':
						//TODO
						return 1;
					case '|':
						//TODO
						return 1;
					default:
						return 1;
				}

				break;
			case 2:
				sig->byte_test[index]->value = atoi(tptr);
				break;
			case 3:
				sig->byte_test[index]->offset = atoi(tptr);
				break;
			default:
				if(strncmp(tptr,"relative",8) == 0) {
					sig->byte_test[index]->relative = 1;
					return 1; // todo
				} else if(strncmp(tptr,"little",6) == 0) {
					sig->byte_test[index]->endian = BYTE_ORDER_LITTLE;
				} else if(strncmp(tptr,"big",3) == 0) {
					sig->byte_test[index]->endian = BYTE_ORDER_BIG;
					return 1; // todo
				} else if(strncmp(tptr,"hex",3) == 0) {
					sig->byte_test[index]->number_type = BYTE_TYPE_HEX;
					return 1; // todo
				} else if(strncmp(tptr,"dec",3) == 0) {
					sig->byte_test[index]->number_type = BYTE_TYPE_DEC;
				} else if(strncmp(tptr,"oct",3) == 0) {
					sig->byte_test[index]->number_type = BYTE_TYPE_OCT;
					return 1; // todo
				} else {
					//printf(" Huh ? default:%d \"%s\"\n",count,tptr);
				}

				break;
		}
	}

	//dump_byte_test(sig->byte_test[index]);

	// byte_test:1,&,16,1,relative;
	// byte_test:4,>,200,36;
	

	return 0;
}


void dump_byte_test (struct byte_test* bt) {

        printf("bytes_to_convert %d\n",bt->bytes_to_convert);
        printf("operator %d\n",bt->operator);
        printf("value %d\n",bt->value);
        printf("offset %d\n",bt->offset);
        printf("relative %d\n",bt->relative);
        printf("endian %d\n",bt->endian);
        printf("string %d\n",bt->string);
        printf("number_type %d\n",bt->number_type);
}

