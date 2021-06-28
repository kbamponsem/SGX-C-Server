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

void print_string(const char *func_name, const char *string, const char *enc_string)
{
	printf("%s: %s\n\t%s\n", func_name, string, enc_string);
}

void enclave1_print_string(char *string)
{
	printf("Enclave 1 Unsecure Print: %s\n", string);
}

void enclave2_print_string(char *string)
{
	printf("Enclave 2 Unsecure Print: %s\n", string);
}

void ocall_printf(char *str)
{
	printf("%s\n", str);
}
big_int get_random_number()
{
	return generate_account_number();
}

void print_number(const char *func_name, big_int number)
{
	printf("%s: %lld\n", func_name, number);
}