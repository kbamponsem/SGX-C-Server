#ifndef USERENCLAVE_U_H__
#define USERENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "/home/kwabena/TaLoS/src/nginx-1.11.0/nginx_sgx_bank/Include/types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef PRINT_STRING_DEFINED__
#define PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, print_string, (const char* func_name, const char* string, const char* enc_string));
#endif
#ifndef PRINT_NUMBER_DEFINED__
#define PRINT_NUMBER_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, print_number, (const char* func_name, big_int number));
#endif
#ifndef GET_RANDOM_NUMBER_DEFINED__
#define GET_RANDOM_NUMBER_DEFINED__
big_int SGX_UBRIDGE(SGX_NOCONVENTION, get_random_number, (void));
#endif
#ifndef PTHREAD_WAIT_TIMEOUT_OCALL_DEFINED__
#define PTHREAD_WAIT_TIMEOUT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_wait_timeout_ocall, (unsigned long long waiter, unsigned long long timeout));
#endif
#ifndef PTHREAD_CREATE_OCALL_DEFINED__
#define PTHREAD_CREATE_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_create_ocall, (unsigned long long self));
#endif
#ifndef PTHREAD_WAKEUP_OCALL_DEFINED__
#define PTHREAD_WAKEUP_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_wakeup_ocall, (unsigned long long waiter));
#endif
#ifndef U_SGXSSL_FTIME_DEFINED__
#define U_SGXSSL_FTIME_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxssl_ftime, (void* timeptr, uint32_t timeb_len));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif

sgx_status_t create_account(sgx_enclave_id_t eid, int* retval, char* username, char* password, big_int acc_number);
sgx_status_t enclave1_generate_keys(sgx_enclave_id_t eid, int* retval);
sgx_status_t enclave1_get_pub_key(sgx_enclave_id_t eid, char* pub_key_cpy);
sgx_status_t enclave1_create_session(sgx_enclave_id_t eid, int* retval, big_int id, const char* encrypted_session_id);
sgx_status_t login(sgx_enclave_id_t eid, int* retval, big_int account_number, char* password);
sgx_status_t get_user_session_id(sgx_enclave_id_t eid, big_int id, char* session_id);
sgx_status_t remove_session_id(sgx_enclave_id_t eid, int* retval, big_int id);
sgx_status_t add_to_registered_users(sgx_enclave_id_t eid, char* username);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
