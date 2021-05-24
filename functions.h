#include <stdio.h>
#include <string.h>
#include "types.h"
#include "utils.h"

#define max(a, b) (a >= b ? a : b)

void *initialize_accounts(char *type)
{
    if (strcmp(type, "users") == 0)
    {
        All_Users *all_users = (All_Users *)calloc(1, sizeof(All_Users));
        all_users->users = (Account_U **)calloc(1, sizeof(Account_U *));

        if (all_users->users == NULL)
        {
            fprintf(stderr, "Unable to allocate memory users\n");
        }
        for (size_t i = 0; i < all_users->size; i++)
        {
            Account_U *user = (Account_U *)calloc(1, sizeof(Account_U));

            user->username = NULL;
            user->account_number = 0;

            all_users->users[i] = user;
        }

        return all_users;
    }

    if (strcmp(type, "balances") == 0)
    {
        All_Balances *all_balances = (All_Balances *)calloc(1, sizeof(All_Balances));
        all_balances->balances = (Account_B **)calloc(1, sizeof(Account_B *));

        if (all_balances->balances == NULL)
        {
            fprintf(stderr, "Unable to allocate memory for balances\n");
        }
        for (size_t i = 0; i < all_balances->size; i++)
        {
            Account_B *balance = (Account_B *)calloc(1, sizeof(Account_B));

            balance->balance = 0;
            balance->account_number = 0;

            all_balances->balances[i] = balance;
        }

        return all_balances;
    }
    else
        return NULL;
}
void show_accounts(Bank *bank)
{
    if (bank == NULL)
    {
        fprintf(stderr, "NEVER\n");
        exit(1);
    }
    size_t list_size = bank->size;

    for (size_t i = 0; i < list_size; i++)
    {
        if ((bank->users[i]->username != NULL && bank->users[i]->account_number != 0) || (bank->balances[i]->balance == 0.0 && bank->balances[i]->account_number != 0))
        {
            printf("%s, %lli\n", bank->users[i]->username, bank->users[i]->account_number);
            printf("%lli, %0.2f\n", bank->balances[i]->account_number, bank->balances[i]->balance);
        }

        else
            continue;
    }
}

json_t *get_all_accounts(All_Users **all_users, All_Balances **all_balances)
{
    json_t *users = json_array();
    json_t *balances = json_array();
    json_t *results = json_object();

    if (*all_users == NULL || *all_balances == NULL)
    {
        json_object_set_new(results, "users", users);
        json_object_set_new(results, "balances", balances);
        return results;
    }
    else
    {
        for (size_t i = 0; i < (*all_users)->size; i++)
        {
            Account_U *user = (*all_users)->users[i];
            Account_B *balance = (*all_balances)->balances[i];

            json_t *user_obj = json_object();
            json_t *balance_obj = json_object();

            if ((user->username == NULL && user->account_number == 0) || (balance->account_number == 0 && balance->balance == 0.0))
                continue;
            else
            {
                show_message("--retrieving working--");

                json_object_set_new(user_obj, "username", json_string(user->username));
                json_object_set_new(user_obj, "account_number", json_integer(user->account_number));

                json_object_set_new(balance_obj, "balance", json_real(balance->balance));
                json_object_set_new(balance_obj, "account_number", json_integer(balance->account_number));

                json_array_append_new(users, user_obj);
                json_array_append_new(balances, balance_obj);
            }
        }

        json_object_set_new(results, "users", users);
        json_object_set_new(results, "balances", balances);
        return results;
    }
}

int add_account(All_Users **all_users, All_Balances **all_balances, Account_U *user, Account_B *balance)
{
    if (*all_users == NULL || *all_balances == NULL)
    {
        *all_users = (All_Users *)initialize_accounts("users");
        *all_balances = (All_Balances *)initialize_accounts("balances");
    }
    // fprintf(stderr, "%s\n", *bank == NULL ? "Bank still NULL." : NULL);
    size_t curr_list_size = max((*all_users)->size, (*all_balances)->size);

    size_t new_list_size = curr_list_size + 1;

    if (user->username != NULL)
    {
        Account_U **curr_users = (*all_users)->users;
        Account_B **curr_balances = (*all_balances)->balances;

        Account_U **new_users = (Account_U **)calloc(new_list_size, sizeof(Account_U *));
        Account_B **new_balances = (Account_B **)calloc(new_list_size, sizeof(Account_B *));

        for (size_t i = 0; i < curr_list_size; i++)
        {

            new_users[i] = curr_users[i];
            new_balances[i] = curr_balances[i];
        }

        (*all_users)->users = new_users;
        (*all_balances)->balances = new_balances;

        show_message("--adding-to-users-and-balances--");
        (*all_users)->users[curr_list_size] = user;
        (*all_balances)->balances[curr_list_size] = balance;

        (*all_users)->size = new_list_size;
        (*all_balances)->size = new_list_size;

        return 1;
    }
    else
        return 0;
}

int delete_account(All_Users **all_users, All_Balances **all_balances, big_int identifier)
{
    if (*all_users == NULL || *all_balances == NULL)
    {
        return 0;
    }
    size_t curr_list_size = max((*all_users)->size, (*all_balances)->size);

    for (size_t i = 0; i < curr_list_size; i++)
    {
        Account_U *user = (Account_U *)calloc(1, sizeof(Account_U));
        Account_B *balance = (Account_B *)calloc(1, sizeof(Account_B));

        user = (*all_users)->users[i];
        balance = (*all_balances)->balances[i];

        if ((user->username != NULL && user->account_number != 0) && (balance->account_number != 0))
        {
            if (user->account_number == identifier && balance->account_number == identifier)
            {
                fprintf(stderr, "%s, %llu\n", user->username, user->account_number);
                user->username = NULL;
                user->account_number = 0;

                balance->account_number = 0;

                (*all_users)->users[i] = user;
                (*all_balances)->balances[i] = balance;

                return 1;
            }
        }
    }

    return 0;
}

int operation(All_Balances** all_balances, big_int account_number, float amount, const char *type)
{
    if (*all_balances == NULL)
    {
        return 0;
    }

    if (amount < 0)
    {
        return 0;
    }
    size_t curr_list_size = max(0, (*all_balances)->size);

    for (size_t i = 0; i < curr_list_size; i++)
    {
        Account_B *_balance = (Account_B *)calloc(1, sizeof(Account_B));

        _balance = (*all_balances)->balances[i];

        if ((_balance->account_number != 0))
        {
            if (_balance->account_number == account_number)
            {
                if (strcmp(type, "WITHDRAW") == 0)
                {
                    if (_balance->balance > 0)
                    {
                        _balance->balance = _balance->balance - amount;
                        (*all_balances)->balances[i] = _balance;
                        return 1;
                    }
                }
                else if (strcmp(type, "DEPOSIT") == 0)
                {
                    _balance->balance = _balance->balance + amount;
                    (*all_balances)->balances[i] = _balance;
                    return 1;
                }
            }
        }
    }

    return 0;
}

// char *c_read_file(const char *f_name, int *err, size_t *f_size)
// {
//     char *buffer;
//     size_t length;
//     FILE *f = fopen(f_name, "rb");
//     size_t read_length;

//     if (f)
//     {
//         fseek(f, 0, SEEK_END);
//         length = ftell(f);
//         fseek(f, 0, SEEK_SET);

//         // 1 GiB; best not to load a whole large file in one string
//         if (length > 1073741824)
//         {
//             *err = FILE_TO_LARGE;

//             return NULL;
//         }

//         buffer = (char *)malloc(length + 1);

//         if (length)
//         {
//             read_length = fread(buffer, 1, length, f);

//             if (length != read_length)
//             {
//                 free(buffer);
//                 *err = FILE_READ_ERROR;

//                 return NULL;
//             }
//         }

//         fclose(f);

//         *err = FILE_OK;
//         buffer[length] = '\0';
//         *f_size = length;
//     }
//     else
//     {
//         *err = FILE_NOT_EXIST;

//         return NULL;
//     }

//     return buffer;
// }