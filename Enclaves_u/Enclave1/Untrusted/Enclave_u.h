#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "../Include/types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef PRINT_ADDR_DEFINED__
#define PRINT_ADDR_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, print_addr, (void* addr));
#endif
#ifndef SERIALIZE_DATA_DEFINED__
#define SERIALIZE_DATA_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, serialize_data, (Account_U** all_users, size_t size));
#endif
#ifndef PRINT_STRING_DEFINED__
#define PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, print_string, (char* string));
#endif

sgx_status_t secure_subtract(sgx_enclave_id_t eid, enclave_op* retval, double a, double b);
sgx_status_t decrypt_message(sgx_enclave_id_t eid, int* retval, char* encrypted_message);
sgx_status_t get_users(sgx_enclave_id_t eid);
sgx_status_t add_user(sgx_enclave_id_t eid, int* retval, Account_U* user);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
