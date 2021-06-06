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

#ifndef PRINT_ADDR_DEFINED__
#define PRINT_ADDR_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, print_addr, (void* addr));
#endif
#ifndef SERIALIZE_USER_DEFINED__
#define SERIALIZE_USER_DEFINED__
char* SGX_UBRIDGE(SGX_NOCONVENTION, serialize_user, (All_Users* all_users));
#endif
#ifndef PRINT_STRING_DEFINED__
#define PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, print_string, (char* string));
#endif
#ifndef USER_STRING_TO_ACCOUNT_DEFINED__
#define USER_STRING_TO_ACCOUNT_DEFINED__
Account_U SGX_UBRIDGE(SGX_NOCONVENTION, user_string_to_account, (char* user_string));
#endif

sgx_status_t get_users(sgx_enclave_id_t eid, char** retval);
sgx_status_t add_user(sgx_enclave_id_t eid, int* retval, char* user_string);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
