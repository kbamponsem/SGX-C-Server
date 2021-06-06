#include "UserEnclave_u.h"
#include <errno.h>

typedef struct ms_get_users_t {
	char* ms_retval;
} ms_get_users_t;

typedef struct ms_add_user_t {
	int ms_retval;
	char* ms_user_string;
} ms_add_user_t;

typedef struct ms_print_addr_t {
	void* ms_addr;
} ms_print_addr_t;

typedef struct ms_serialize_user_t {
	char* ms_retval;
	All_Users* ms_all_users;
} ms_serialize_user_t;

typedef struct ms_print_string_t {
	char* ms_string;
} ms_print_string_t;

typedef struct ms_user_string_to_account_t {
	Account_U ms_retval;
	char* ms_user_string;
} ms_user_string_to_account_t;

static sgx_status_t SGX_CDECL UserEnclave_print_addr(void* pms)
{
	ms_print_addr_t* ms = SGX_CAST(ms_print_addr_t*, pms);
	print_addr(ms->ms_addr);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL UserEnclave_serialize_user(void* pms)
{
	ms_serialize_user_t* ms = SGX_CAST(ms_serialize_user_t*, pms);
	ms->ms_retval = serialize_user(ms->ms_all_users);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL UserEnclave_print_string(void* pms)
{
	ms_print_string_t* ms = SGX_CAST(ms_print_string_t*, pms);
	print_string(ms->ms_string);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL UserEnclave_user_string_to_account(void* pms)
{
	ms_user_string_to_account_t* ms = SGX_CAST(ms_user_string_to_account_t*, pms);
	ms->ms_retval = user_string_to_account(ms->ms_user_string);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[4];
} ocall_table_UserEnclave = {
	4,
	{
		(void*)UserEnclave_print_addr,
		(void*)UserEnclave_serialize_user,
		(void*)UserEnclave_print_string,
		(void*)UserEnclave_user_string_to_account,
	}
};
sgx_status_t get_users(sgx_enclave_id_t eid, char** retval)
{
	sgx_status_t status;
	ms_get_users_t ms;
	status = sgx_ecall(eid, 0, &ocall_table_UserEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t add_user(sgx_enclave_id_t eid, int* retval, char* user_string)
{
	sgx_status_t status;
	ms_add_user_t ms;
	ms.ms_user_string = user_string;
	status = sgx_ecall(eid, 1, &ocall_table_UserEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

