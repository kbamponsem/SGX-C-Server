#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_secure_subtract_t {
	enclave_op ms_retval;
	double ms_a;
	double ms_b;
} ms_secure_subtract_t;

typedef struct ms_decrypt_message_t {
	int ms_retval;
	char* ms_encrypted_message;
} ms_decrypt_message_t;

typedef struct ms_add_user_t {
	int ms_retval;
	Account_U* ms_user;
} ms_add_user_t;

typedef struct ms_print_addr_t {
	void* ms_addr;
} ms_print_addr_t;

typedef struct ms_serialize_data_t {
	Account_U** ms_all_users;
	size_t ms_size;
} ms_serialize_data_t;

typedef struct ms_print_string_t {
	char* ms_string;
} ms_print_string_t;

static sgx_status_t SGX_CDECL Enclave_print_addr(void* pms)
{
	ms_print_addr_t* ms = SGX_CAST(ms_print_addr_t*, pms);
	print_addr(ms->ms_addr);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_serialize_data(void* pms)
{
	ms_serialize_data_t* ms = SGX_CAST(ms_serialize_data_t*, pms);
	serialize_data(ms->ms_all_users, ms->ms_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_print_string(void* pms)
{
	ms_print_string_t* ms = SGX_CAST(ms_print_string_t*, pms);
	print_string(ms->ms_string);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[3];
} ocall_table_Enclave = {
	3,
	{
		(void*)Enclave_print_addr,
		(void*)Enclave_serialize_data,
		(void*)Enclave_print_string,
	}
};
sgx_status_t secure_subtract(sgx_enclave_id_t eid, enclave_op* retval, double a, double b)
{
	sgx_status_t status;
	ms_secure_subtract_t ms;
	ms.ms_a = a;
	ms.ms_b = b;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t decrypt_message(sgx_enclave_id_t eid, int* retval, char* encrypted_message)
{
	sgx_status_t status;
	ms_decrypt_message_t ms;
	ms.ms_encrypted_message = encrypted_message;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t get_users(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t add_user(sgx_enclave_id_t eid, int* retval, Account_U* user)
{
	sgx_status_t status;
	ms_add_user_t ms;
	ms.ms_user = user;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

