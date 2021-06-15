#include <stdio.h>
#include <jansson.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>

void print_addr(void *addr)
{
	printf("Addr: %p\n", addr);
}

void print_string(char *string)
{
	printf("Unsecure Print: %s\n", string);
}

big_int get_random_number() {
	return generate_account_number();
}