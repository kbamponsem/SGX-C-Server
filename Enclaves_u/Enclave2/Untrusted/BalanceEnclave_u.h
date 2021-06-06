#ifndef BALANCEENCLAVE_U_H__
#define BALANCEENCLAVE_U_H__

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

#ifndef SERIALIZE_BALANCE_DEFINED__
#define SERIALIZE_BALANCE_DEFINED__
char* SGX_UBRIDGE(SGX_NOCONVENTION, serialize_balance, (All_Balances* all_balances));
#endif
#ifndef BALANCE_STRING_TO_ACCOUNT_DEFINED__
#define BALANCE_STRING_TO_ACCOUNT_DEFINED__
Account_B SGX_UBRIDGE(SGX_NOCONVENTION, balance_string_to_account, (char* balance_string));
#endif

sgx_status_t get_balances(sgx_enclave_id_t eid, char** retval);
sgx_status_t add_balance(sgx_enclave_id_t eid, int* retval, char* balance_string);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
