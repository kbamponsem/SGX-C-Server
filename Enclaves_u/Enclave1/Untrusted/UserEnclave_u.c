#include "UserEnclave_u.h"
#include <errno.h>

typedef struct ms_create_account_t {
	int ms_retval;
	char* ms_username;
	char* ms_password;
	big_int ms_acc_number;
} ms_create_account_t;

typedef struct ms_enclave1_generate_keys_t {
	int ms_retval;
} ms_enclave1_generate_keys_t;

typedef struct ms_enclave1_get_pub_key_t {
	char* ms_pub_key_cpy;
} ms_enclave1_get_pub_key_t;

typedef struct ms_enclave1_create_session_t {
	int ms_retval;
	big_int ms_id;
	const char* ms_encrypted_session_id;
} ms_enclave1_create_session_t;

typedef struct ms_login_t {
	int ms_retval;
	big_int ms_account_number;
	char* ms_password;
} ms_login_t;

typedef struct ms_get_user_session_id_t {
	big_int ms_id;
	char* ms_session_id;
} ms_get_user_session_id_t;

typedef struct ms_remove_session_id_t {
	int ms_retval;
	big_int ms_id;
} ms_remove_session_id_t;

typedef struct ms_add_to_registered_users_t {
	char* ms_username;
} ms_add_to_registered_users_t;

typedef struct ms_print_string_t {
	const char* ms_func_name;
	const char* ms_string;
	const char* ms_enc_string;
} ms_print_string_t;

typedef struct ms_print_number_t {
	const char* ms_func_name;
	big_int ms_number;
} ms_print_number_t;

typedef struct ms_get_random_number_t {
	big_int ms_retval;
} ms_get_random_number_t;

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

static sgx_status_t SGX_CDECL UserEnclave_print_string(void* pms)
{
	ms_print_string_t* ms = SGX_CAST(ms_print_string_t*, pms);
	print_string(ms->ms_func_name, ms->ms_string, ms->ms_enc_string);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL UserEnclave_print_number(void* pms)
{
	ms_print_number_t* ms = SGX_CAST(ms_print_number_t*, pms);
	print_number(ms->ms_func_name, ms->ms_number);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL UserEnclave_get_random_number(void* pms)
{
	ms_get_random_number_t* ms = SGX_CAST(ms_get_random_number_t*, pms);
	ms->ms_retval = get_random_number();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL UserEnclave_pthread_wait_timeout_ocall(void* pms)
{
	ms_pthread_wait_timeout_ocall_t* ms = SGX_CAST(ms_pthread_wait_timeout_ocall_t*, pms);
	ms->ms_retval = pthread_wait_timeout_ocall(ms->ms_waiter, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL UserEnclave_pthread_create_ocall(void* pms)
{
	ms_pthread_create_ocall_t* ms = SGX_CAST(ms_pthread_create_ocall_t*, pms);
	ms->ms_retval = pthread_create_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL UserEnclave_pthread_wakeup_ocall(void* pms)
{
	ms_pthread_wakeup_ocall_t* ms = SGX_CAST(ms_pthread_wakeup_ocall_t*, pms);
	ms->ms_retval = pthread_wakeup_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL UserEnclave_u_sgxssl_ftime(void* pms)
{
	ms_u_sgxssl_ftime_t* ms = SGX_CAST(ms_u_sgxssl_ftime_t*, pms);
	u_sgxssl_ftime(ms->ms_timeptr, ms->ms_timeb_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL UserEnclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL UserEnclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL UserEnclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL UserEnclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL UserEnclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[12];
} ocall_table_UserEnclave = {
	12,
	{
		(void*)UserEnclave_print_string,
		(void*)UserEnclave_print_number,
		(void*)UserEnclave_get_random_number,
		(void*)UserEnclave_pthread_wait_timeout_ocall,
		(void*)UserEnclave_pthread_create_ocall,
		(void*)UserEnclave_pthread_wakeup_ocall,
		(void*)UserEnclave_u_sgxssl_ftime,
		(void*)UserEnclave_sgx_oc_cpuidex,
		(void*)UserEnclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)UserEnclave_sgx_thread_set_untrusted_event_ocall,
		(void*)UserEnclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)UserEnclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t create_account(sgx_enclave_id_t eid, int* retval, char* username, char* password, big_int acc_number)
{
	sgx_status_t status;
	ms_create_account_t ms;
	ms.ms_username = username;
	ms.ms_password = password;
	ms.ms_acc_number = acc_number;
	status = sgx_ecall(eid, 0, &ocall_table_UserEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave1_generate_keys(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_enclave1_generate_keys_t ms;
	status = sgx_ecall(eid, 1, &ocall_table_UserEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave1_get_pub_key(sgx_enclave_id_t eid, char* pub_key_cpy)
{
	sgx_status_t status;
	ms_enclave1_get_pub_key_t ms;
	ms.ms_pub_key_cpy = pub_key_cpy;
	status = sgx_ecall(eid, 2, &ocall_table_UserEnclave, &ms);
	return status;
}

sgx_status_t enclave1_create_session(sgx_enclave_id_t eid, int* retval, big_int id, const char* encrypted_session_id)
{
	sgx_status_t status;
	ms_enclave1_create_session_t ms;
	ms.ms_id = id;
	ms.ms_encrypted_session_id = encrypted_session_id;
	status = sgx_ecall(eid, 3, &ocall_table_UserEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t login(sgx_enclave_id_t eid, int* retval, big_int account_number, char* password)
{
	sgx_status_t status;
	ms_login_t ms;
	ms.ms_account_number = account_number;
	ms.ms_password = password;
	status = sgx_ecall(eid, 4, &ocall_table_UserEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t get_user_session_id(sgx_enclave_id_t eid, big_int id, char* session_id)
{
	sgx_status_t status;
	ms_get_user_session_id_t ms;
	ms.ms_id = id;
	ms.ms_session_id = session_id;
	status = sgx_ecall(eid, 5, &ocall_table_UserEnclave, &ms);
	return status;
}

sgx_status_t remove_session_id(sgx_enclave_id_t eid, int* retval, big_int id)
{
	sgx_status_t status;
	ms_remove_session_id_t ms;
	ms.ms_id = id;
	status = sgx_ecall(eid, 6, &ocall_table_UserEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t add_to_registered_users(sgx_enclave_id_t eid, char* username)
{
	sgx_status_t status;
	ms_add_to_registered_users_t ms;
	ms.ms_username = username;
	status = sgx_ecall(eid, 7, &ocall_table_UserEnclave, &ms);
	return status;
}

