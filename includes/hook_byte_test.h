#ifndef __HOOK_BYTE_TEST_H
#define __HOOK_BYTE_TEST_H

#define BYTE_OPERATOR_LT	1	// <
#define BYTE_OPERATOR_GT	2	// >
#define BYTE_OPERATOR_EQ	3	// =
#define BYTE_OPERATOR_NOT	4	// !
#define BYTE_OPERATOR_AND	5	// &
#define BYTE_OPERATOR_OR	6	// ^

#define BYTE_ORDER_LITTLE	1
#define BYTE_ORDER_BIG		2

#define BYTE_TYPE_HEX		1
#define BYTE_TYPE_DEC		2
#define BYTE_TYPE_OCT		3

#define BYTE_MAX_DIGIT		30

// byte_test:1,&,16,1,relative;
// byte_test:4,>,200,36;

struct byte_test {

	int bytes_to_convert;
	int operator;
	int value;
	int offset;
	int relative;
	int endian;
	int string;
	int number_type;	

};

int hook_byte_test(struct signature *sig,struct traffic *traffic);
int hook_byte_test_options(char *key, char *val, struct signature *sig);
int do_byte_test (struct byte_test *bptr, struct traffic *traffic, long digit);


#endif
