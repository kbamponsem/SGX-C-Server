#include <stdlib.h>

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
} Account_U;

typedef struct
{
    float balance;
    big_int account_number;
} Account_B;

typedef struct
{
    Account_U users[1000];
    size_t size;
} All_Users;

typedef struct
{
    Account_B balances[1000];
    size_t size;
} All_Balances;