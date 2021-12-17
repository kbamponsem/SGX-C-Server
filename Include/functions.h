#ifndef FUNCTIONS_H__
#define FUNCTIONS_H__

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <pwd.h>
#include "sgx_urts.h"
#include "sgx_error.h" /* sgx_status_t */
#include "sgx_eid.h"   /* sgx_enclave_id_t */
#include "sgx_trts.h"

#include "../Enclaves_u/Enclave1/Untrusted/UserEnclave_u.h"
#include "../Enclaves_u/Enclave2/Untrusted/BalanceEnclave_u.h"

#define MAX_PATH FILENAME_MAX

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define max(a, b) (a >= b ? a : b)


static int initialize_bank_enclave(const char* ENCLAVE_FILENAME, const char* TOKEN_FILENAME, sgx_enclave_id_t *enclave_id)
{
	char token_path[MAX_PATH] = {'\0'};
	sgx_launch_token_t token = {0};
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int updated = 0;

	const char *home_dir = getpwuid(getuid())->pw_dir;
    
    strcpy(token_path, TOKEN_FILENAME);


	FILE *fp = fopen(token_path, "rb");
	if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL)
	{
		printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
	}

	if (fp != NULL)
	{
		/* read the token from saved file */
		size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
		if (read_num != 0 && read_num != sizeof(sgx_launch_token_t))
		{
			/* if token is invalid, clear the buffer */
			memset(&token, 0x0, sizeof(sgx_launch_token_t));
			printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
		}
	}
	/* Step 2: call sgx_create_enclave to initialize an enclave instance */
	/* Debug Support: set 2nd parameter to 1 */
	ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, enclave_id, NULL);
	if (ret != SGX_SUCCESS)
	{
		printf("ERROR!\n");
		if (fp != NULL)
			fclose(fp);
		return -1;
	}

	/* Step 3: save the launch token if it is updated */
	if (updated == FALSE || fp == NULL)
	{
		/* if the token is not updated, or file handler is invalid, do not perform saving */
		if (fp != NULL)
			fclose(fp);
		return 0;
	}

	/* reopen the file with write capablity */
	fp = freopen(token_path, "wb", fp);
	if (fp == NULL)
		return 0;
	size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
	if (write_num != sizeof(sgx_launch_token_t))
		printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
	fclose(fp);
	return 0;
}
#endif