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

void enclave1_print_string(char *string)
{
	printf("Enclave 1 Unsecure Print: %s\n", string);
}

void enclave2_print_string(char *string)
{
	printf("Enclave 2 Unsecure Print: %s\n", string);
}
big_int get_random_number()
{
	return generate_account_number();
}

void print_number(big_int number)
{
	printf("Unsecure Print: %lld\n", number);
}