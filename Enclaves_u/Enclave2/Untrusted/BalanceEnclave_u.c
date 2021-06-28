#include "BalanceEnclave_u.h"
#include <errno.h>

typedef struct ms_enclave2_create_session_t {
	int ms_retval;
	big_int ms_id;
	char* ms_encrypted_session_id;
	size_t ms_encrypted_session_id_len;
} ms_enclave2_create_session_t;

typedef struct ms_enclave2_get_pub_key_t {
	char* ms_pub_key_cpy;
} ms_enclave2_get_pub_key_t;

typedef struct ms_enclave2_generate_keys_t {
	int ms_retval;
} ms_enclave2_generate_keys_t;

typedef struct ms_get_balance_t {
	int ms_retval;
	big_int ms_id;
	char* ms_balance_string;
} ms_get_balance_t;

typedef struct ms_enclave2_print_string_t {
	char* ms_string;
} ms_enclave2_print_string_t;

typedef struct ms_print_number_t {
	const char* ms_func_name;
	big_int ms_number;
} ms_print_number_t;

typedef struct ms_pthread_wait_timeout_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
	unsigned long long ms_timeout;
} ms_pthread_wait_timeout_ocall_t;

typedef struct ms_pthread_create_ocall_t {
	int ms_retval;
	unsigned long long ms_self;
} ms_pthread_create_ocall_t;

typedef struct ms_pthread_wakeup_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
} ms_pthread_wakeup_ocall_t;

typedef struct ms_u_sgxssl_ftime_t {
	void* ms_timeptr;
	uint32_t ms_timeb_len;
} ms_u_sgxssl_ftime_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL BalanceEnclave_enclave2_print_string(void* pms)
{
	ms_enclave2_print_string_t* ms = SGX_CAST(ms_enclave2_print_string_t*, pms);
	enclave2_print_string(ms->ms_string);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL BalanceEnclave_print_number(void* pms)
{
	ms_print_number_t* ms = SGX_CAST(ms_print_number_t*, pms);
	print_number(ms->ms_func_name, ms->ms_number);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL BalanceEnclave_pthread_wait_timeout_ocall(void* pms)
{
	ms_pthread_wait_timeout_ocall_t* ms = SGX_CAST(ms_pthread_wait_timeout_ocall_t*, pms);
	ms->ms_retval = pthread_wait_timeout_ocall(ms->ms_waiter, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL BalanceEnclave_pthread_create_ocall(void* pms)
{
	ms_pthread_create_ocall_t* ms = SGX_CAST(ms_pthread_create_ocall_t*, pms);
	ms->ms_retval = pthread_create_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL BalanceEnclave_pthread_wakeup_ocall(void* pms)
{
	ms_pthread_wakeup_ocall_t* ms = SGX_CAST(ms_pthread_wakeup_ocall_t*, pms);
	ms->ms_retval = pthread_wakeup_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL BalanceEnclave_u_sgxssl_ftime(void* pms)
{
	ms_u_sgxssl_ftime_t* ms = SGX_CAST(ms_u_sgxssl_ftime_t*, pms);
	u_sgxssl_ftime(ms->ms_timeptr, ms->ms_timeb_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL BalanceEnclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL BalanceEnclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL BalanceEnclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL BalanceEnclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL BalanceEnclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[11];
} ocall_table_BalanceEnclave = {
	11,
	{
		(void*)BalanceEnclave_enclave2_print_string,
		(void*)BalanceEnclave_print_number,
		(void*)BalanceEnclave_pthread_wait_timeout_ocall,
		(void*)BalanceEnclave_pthread_create_ocall,
		(void*)BalanceEnclave_pthread_wakeup_ocall,
		(void*)BalanceEnclave_u_sgxssl_ftime,
		(void*)BalanceEnclave_sgx_oc_cpuidex,
		(void*)BalanceEnclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)BalanceEnclave_sgx_thread_set_untrusted_event_ocall,
		(void*)BalanceEnclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)BalanceEnclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t enclave2_create_session(sgx_enclave_id_t eid, int* retval, big_int id, char* encrypted_session_id)
{
	sgx_status_t status;
	ms_enclave2_create_session_t ms;
	ms.ms_id = id;
	ms.ms_encrypted_session_id = encrypted_session_id;
	ms.ms_encrypted_session_id_len = encrypted_session_id ? strlen(encrypted_session_id) + 1 : 0;
	status = sgx_ecall(eid, 0, &ocall_table_BalanceEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave2_get_pub_key(sgx_enclave_id_t eid, char* pub_key_cpy)
{
	sgx_status_t status;
	ms_enclave2_get_pub_key_t ms;
	ms.ms_pub_key_cpy = pub_key_cpy;
	status = sgx_ecall(eid, 1, &ocall_table_BalanceEnclave, &ms);
	return status;
}

sgx_status_t enclave2_generate_keys(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_enclave2_generate_keys_t ms;
	status = sgx_ecall(eid, 2, &ocall_table_BalanceEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t get_balance(sgx_enclave_id_t eid, int* retval, big_int id, char* balance_string)
{
	sgx_status_t status;
	ms_get_balance_t ms;
	ms.ms_id = id;
	ms.ms_balance_string = balance_string;
	status = sgx_ecall(eid, 3, &ocall_table_BalanceEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

