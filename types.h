#include <stdlib.h>

#define FILE_OK 0
#define FILE_NOT_EXIST 1
#define FILE_TO_LARGE 2
#define FILE_READ_ERROR 3

typedef long long big_int;

typedef struct
{
    const char *username;
    big_int account_number;
} Account_U;

typedef struct
{
    float balance;
    big_int account_number;
} Account_B;

typedef struct
{
    Account_U **users;
    Account_B **balances;
    size_t size;
} Bank;

typedef struct
{
    Account_U **users;
    size_t size;
} All_Users;

typedef struct
{
    Account_B **balances;
    size_t size;
} All_Balances;