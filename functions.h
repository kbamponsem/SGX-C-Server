#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <pwd.h>
#include "utils.h"
#include "sgx_urts.h"
#include "sgx_error.h" /* sgx_status_t */
#include "sgx_eid.h"   /* sgx_enclave_id_t */
#include "sgx_trts.h"

#include "Enclaves_u/Enclave1/Untrusted/Enclave_u.h"
#include "Enclaves_u/Enclave2/Untrusted/Enclave_u.h"



#define MAX_PATH FILENAME_MAX

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define max(a, b) (a >= b ? a : b)

// void *initialize_accounts(char *type)
// {
//     if (strcmp(type, "users") == 0)
//     {
//         All_Users *all_users = (All_Users *)calloc(1, sizeof(All_Users));
//         all_users->users = (Account_U **)calloc(1, sizeof(Account_U *));

//         if (all_users->users == NULL)
//         {
//             fprintf(stderr, "Unable to allocate memory users\n");
//         }
//         for (size_t i = 0; i < all_users->size; i++)
//         {
//             Account_U *user = (Account_U *)calloc(1, sizeof(Account_U));

//             user->username = NULL;
//             user->account_number = 0;

//             all_users->users[i] = user;
//         }

//         return all_users;
//     }

//     if (strcmp(type, "balances") == 0)
//     {
//         All_Balances *all_balances = (All_Balances *)calloc(1, sizeof(All_Balances));
//         all_balances->balances = (Account_B **)calloc(1, sizeof(Account_B *));

//         if (all_balances->balances == NULL)
//         {
//             fprintf(stderr, "Unable to allocate memory for balances\n");
//         }
//         for (size_t i = 0; i < all_balances->size; i++)
//         {
//             Account_B *balance = (Account_B *)calloc(1, sizeof(Account_B));

//             balance->balance = 0;
//             balance->account_number = 0;

//             all_balances->balances[i] = balance;
//         }

//         return all_balances;
//     }
//     else
//         return NULL;
// }

json_t *get_users_as_json(All_Users *all_users)
{
    json_t *users = json_array();
    json_t *results = json_object();

    if (all_users == NULL)
    {
        json_object_set_new(results, "users", users);
        return results;
    }
    else
    {
        for (size_t i = 0; i < all_users->size; i++)
        {
            Account_U *user = all_users->users[i];

            json_t *user_obj = json_object();
            json_t *balance_obj = json_object();

            if ((user->username == NULL && user->account_number == 0))
                continue;
            else
            {
                show_message("--retrieving working--");

                json_object_set_new(user_obj, "username", json_string(user->username));
                json_object_set_new(user_obj, "account_number", json_integer(user->account_number));

                json_array_append_new(users, user_obj);
            }
        }

        json_object_set_new(results, "users", users);
        return results;
    }
}

// int add_account(All_Users **all_users, All_Balances **all_balances, Account_U *user, Account_B *balance)
// {
//     if (*all_users == NULL || *all_balances == NULL)
//     {
//         *all_users = (All_Users *)initialize_accounts("users");
//         *all_balances = (All_Balances *)initialize_accounts("balances");
//     }
//     // fprintf(stderr, "%s\n", *bank == NULL ? "Bank still NULL." : NULL);
//     size_t curr_list_size = max((*all_users)->size, (*all_balances)->size);

//     size_t new_list_size = curr_list_size + 1;

//     if (user->username != NULL)
//     {
//         Account_U **curr_users = (*all_users)->users;
//         Account_B **curr_balances = (*all_balances)->balances;

//         Account_U **new_users = (Account_U **)calloc(new_list_size, sizeof(Account_U *));
//         Account_B **new_balances = (Account_B **)calloc(new_list_size, sizeof(Account_B *));

//         for (size_t i = 0; i < curr_list_size; i++)
//         {

//             new_users[i] = curr_users[i];
//             new_balances[i] = curr_balances[i];
//         }

//         (*all_users)->users = new_users;
//         (*all_balances)->balances = new_balances;

//         show_message("--adding-to-users-and-balances--");
//         (*all_users)->users[curr_list_size] = user;
//         (*all_balances)->balances[curr_list_size] = balance;

//         (*all_users)->size = new_list_size;
//         (*all_balances)->size = new_list_size;

//         return 1;
//     }
//     else
//         return 0;
// }

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

int initialize_bank_enclave(const char* ENCLAVE_FILENAME, const char* TOKEN_FILENAME, sgx_enclave_id_t *enclave_id)
{
	char token_path[MAX_PATH] = {'\0'};
	sgx_launch_token_t token = {0};
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int updated = 0;

	const char *home_dir = getpwuid(getuid())->pw_dir;
    
    strcpy(token_path, TOKEN_FILENAME);


	FILE *fp = fopen(token_path, "rb");
	if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL)
	{
		printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
	}

	if (fp != NULL)
	{
		/* read the token from saved file */
		size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
		if (read_num != 0 && read_num != sizeof(sgx_launch_token_t))
		{
			/* if token is invalid, clear the buffer */
			memset(&token, 0x0, sizeof(sgx_launch_token_t));
			printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
		}
	}
	/* Step 2: call sgx_create_enclave to initialize an enclave instance */
	/* Debug Support: set 2nd parameter to 1 */
	ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, enclave_id, NULL);
	if (ret != SGX_SUCCESS)
	{
		printf("ERROR!\n");
		if (fp != NULL)
			fclose(fp);
		return -1;
	}

	/* Step 3: save the launch token if it is updated */
	if (updated == FALSE || fp == NULL)
	{
		/* if the token is not updated, or file handler is invalid, do not perform saving */
		if (fp != NULL)
			fclose(fp);
		return 0;
	}

	/* reopen the file with write capablity */
	fp = freopen(token_path, "wb", fp);
	if (fp == NULL)
		return 0;
	size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
	if (write_num != sizeof(sgx_launch_token_t))
		printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
	fclose(fp);
	return 0;
}