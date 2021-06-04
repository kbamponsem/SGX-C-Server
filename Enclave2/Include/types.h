#include <stdlib.h>

typedef struct
{
    double output;
    int status;
} enclave_op;

typedef long long big_int;

typedef struct
{
    float balance;
    big_int account_number;
} Account_B;

typedef struct
{
    Account_B **balances;
    size_t size;
} All_Balances;