#include <stdio.h>
#include <string.h>
#include "types.h"

size_t generate_account_number()
{
    return 1000000000 + rand() / (RAND_MAX / (2000000000 - 1000000000 + 1) + 1);
}
void to_string(json_t *obj)
{
    const char *key;
    json_t *value;
    json_object_foreach(obj, key, value)
    {
        fprintf(stderr, "%s, %s\n", key, json_string_value(value));
    }
}
void initialize_accounts(Bank *bank)
{

    for (size_t i = 0; i < bank->size; i++)
    {
        Account *user = (Account *)calloc(1, sizeof(Account));
        user->username = NULL;
        user->account_number = 0;
        user->balance = 0.0;

        bank->accounts[i] = user;
    }
}
json_t *get_all_accounts(Bank *bank)
{
    json_t *results = json_array();
    int i;

    if (bank == NULL)
    {
        return json_array();
    }
    else
    {
        for (i = 0; i < bank->size; i++)
        {
            Account *user = bank->accounts[i];
            json_t *obj = json_object();

            if (user->username == NULL && user->account_number == 0)
                continue;
            else
            {

                json_object_set_new(obj, "username", json_string(user->username));
                json_object_set_new(obj, "account_number", json_integer(user->account_number));
                json_object_set_new(obj, "balance", json_real(user->balance));
            }

            json_array_append(results, obj);
            json_decref(obj);
        }

        return results;
    }
}

void show_accounts(Bank *bank)
{
    size_t list_size = bank->size;

    int i;

    for (i = 0; i < list_size; i++)
    {
        if (bank->accounts[i]->username != NULL && bank->accounts[i]->account_number != 0)
            printf("%s, %lu, %0.2f\n", bank->accounts[i]->username, bank->accounts[i]->account_number, bank->accounts[i]->balance);
        else
            continue;
    }
}

int add_account(Bank *bank, Account *user)
{
    if (bank == NULL)
    {
        return 0;
    }
    size_t curr_list_size = bank->size;

    size_t new_list_size = curr_list_size + 1;

    Account **curr_users = bank->accounts;

    Account **new_accounts = (Account **)calloc(new_list_size, sizeof(Account *));

    int i;

    for (i = 0; i < curr_list_size; i++)
    {
        new_accounts[i] = curr_users[i];
    }

    bank->accounts = new_accounts;
    bank->accounts[curr_list_size] = user;
    bank->size = new_list_size;

    return 1;
}

int delete_account(Bank *bank, size_t identifier)
{
    size_t curr_list_size = bank->size;

    for (size_t i = 0; i < curr_list_size; i++)
    {
        Account *user = (Account *)calloc(1, sizeof(Account));

        user = bank->accounts[i];

        if (user->username != NULL && user->account_number != 0)
        {
            if (user->account_number == identifier)
            {
                fprintf(stderr, "%s, %lu\n", user->username, user->account_number);
                user->username = NULL;
                user->account_number = 0;

                bank->accounts[i] = user;
                return 1;
            }
        }
    }

    return 0;
}

int operation(Bank *bank, size_t account_number, float amount, const char *type)
{
    size_t curr_list_size = bank->size;

    for (size_t i = 0; i < curr_list_size; i++)
    {
        Account *user = (Account *)calloc(1, sizeof(Account));

        user = bank->accounts[i];

        if (user->username != NULL && user->account_number != 0)
        {
            if (user->account_number == account_number)
            {
                if (strcmp(type, "WITHDRAW") == 0)
                {
                    if (user->balance > 0)
                    {
                        user->balance -= amount;
                        bank->accounts[i] = user;
                        return 1;
                    }
                }
                else if (strcmp(type, "DEPOSIT") == 0)
                {
                    user->balance += amount;
                    bank->accounts[i] = user;
                    return 1;
                }
            }
        }
    }

    return 0;
}

char *c_read_file(const char *f_name, int *err, size_t *f_size)
{
    char *buffer;
    size_t length;
    FILE *f = fopen(f_name, "rb");
    size_t read_length;

    if (f)
    {
        fseek(f, 0, SEEK_END);
        length = ftell(f);
        fseek(f, 0, SEEK_SET);

        // 1 GiB; best not to load a whole large file in one string
        if (length > 1073741824)
        {
            *err = FILE_TO_LARGE;

            return NULL;
        }

        buffer = (char *)malloc(length + 1);

        if (length)
        {
            read_length = fread(buffer, 1, length, f);

            if (length != read_length)
            {
                free(buffer);
                *err = FILE_READ_ERROR;

                return NULL;
            }
        }

        fclose(f);

        *err = FILE_OK;
        buffer[length] = '\0';
        *f_size = length;
    }
    else
    {
        *err = FILE_NOT_EXIST;

        return NULL;
    }

    return buffer;
}