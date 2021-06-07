#ifndef NGX_SGX_BANK_TYPES_H__
#define NGX_SGX_BANK_TYPES_H__

#include <stdlib.h>

#define MAX_SIZE 100000
typedef struct
{
    double output;
    int status;
} enclave_op;

typedef long long big_int;

typedef struct
{
    char *username;
    big_int account_number;
    int deleted;
} Account_U;

typedef struct
{
    float balance;
    big_int account_number;
    int deleted;
} Account_B;

typedef struct
{
    Account_U users[MAX_SIZE];
    size_t size;
} All_Users;

typedef struct
{
    Account_B balances[MAX_SIZE];
    size_t size;
} All_Balances;

typedef struct {
    char *type;
    big_int account_number;
    float amount;
} Balance_Entry;

typedef struct {
    big_int account_number;
} Delete_Entry;

#endif