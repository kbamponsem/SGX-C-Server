#include <stdlib.h>

#define FILE_OK 0
#define FILE_NOT_EXIST 1
#define FILE_TO_LARGE 2
#define FILE_READ_ERROR 3

typedef struct
{
    const char *username;
    float balance;
    size_t account_number;
} Account;

typedef struct
{
    Account **accounts;
    size_t size;
} Bank;