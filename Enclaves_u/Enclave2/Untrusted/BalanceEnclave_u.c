#include "BalanceEnclave_u.h"
#include <errno.h>

typedef struct ms_get_balances_t {
	char* ms_retval;
} ms_get_balances_t;

typedef struct ms_add_balance_t {
	int ms_retval;
	char* ms_balance_string;
} ms_add_balance_t;

typedef struct ms_serialize_balance_t {
	char* ms_retval;
	All_Balances* ms_all_balances;
} ms_serialize_balance_t;

typedef struct ms_balance_string_to_account_t {
	Account_B ms_retval;
	char* ms_balance_string;
} ms_balance_string_to_account_t;

static sgx_status_t SGX_CDECL BalanceEnclave_serialize_balance(void* pms)
{
	ms_serialize_balance_t* ms = SGX_CAST(ms_serialize_balance_t*, pms);
	ms->ms_retval = serialize_balance(ms->ms_all_balances);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL BalanceEnclave_balance_string_to_account(void* pms)
{
	ms_balance_string_to_account_t* ms = SGX_CAST(ms_balance_string_to_account_t*, pms);
	ms->ms_retval = balance_string_to_account(ms->ms_balance_string);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[2];
} ocall_table_BalanceEnclave = {
	2,
	{
		(void*)BalanceEnclave_serialize_balance,
		(void*)BalanceEnclave_balance_string_to_account,
	}
};
sgx_status_t get_balances(sgx_enclave_id_t eid, char** retval)
{
	sgx_status_t status;
	ms_get_balances_t ms;
	status = sgx_ecall(eid, 0, &ocall_table_BalanceEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t add_balance(sgx_enclave_id_t eid, int* retval, char* balance_string)
{
	sgx_status_t status;
	ms_add_balance_t ms;
	ms.ms_balance_string = balance_string;
	status = sgx_ecall(eid, 1, &ocall_table_BalanceEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

