#ifndef NGX_SGX_BANK_TYPES_H__
#define NGX_SGX_BANK_TYPES_H__

#include <stdlib.h>
#define MAX_SIZE 100000

typedef unsigned char u_char;

typedef struct
{
    double output;
    int status;
} enclave_op;

typedef long long big_int;

typedef struct
{
    char *username;
    char *password;
    big_int account_number;
} Account_U;

typedef struct
{
    big_int account_number;
    float balance;
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

struct SessionEntry
{
    big_int id;
    char *session_id;
    struct SessionEntry *left_entry;
    struct SessionEntry *right_entry;
};

typedef struct SessionEntry SessionEntry;

#endif