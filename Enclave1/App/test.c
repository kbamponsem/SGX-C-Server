/**
 * test.c
 * Small Hello World! example
 * to compile with gcc, run the following command
 * gcc -o test test.c -lulfius
 */
#include <stdio.h>
#include <ulfius.h>
#include <string.h>
#include <jansson.h>

#define PORT 8080

typedef struct
{
    char *username;
    char *account_number;
} Account;

typedef struct
{
    Account **accounts;
    size_t size;
} Bank;

void initialize_accounts(Bank *bank)
{

    for (size_t i = 0; i < bank->size; i++)
    {
        Account *user = (Account *)calloc(1, sizeof(Account));
        user->username = NULL;
        user->account_number = NULL;

        bank->accounts[i] = user;
    }
}

void show_accounts(Bank *bank)
{
    size_t list_size = bank->size;

    int i;

    for (i = 0; i < list_size; i++)
    {
        if (bank->accounts[i]->username != NULL && bank->accounts[i]->account_number != NULL)
            printf("%s, %s\n", bank->accounts[i]->username, bank->accounts[i]->account_number);
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

int delete_account(Bank *bank, char *identifier)
{
    size_t curr_list_size = bank->size;

    for (size_t i = 0; i < curr_list_size; i++)
    {
        Account *user = (Account *)calloc(1, sizeof(Account));

        user = bank->accounts[i];

        if (user->username != NULL && user->account_number != NULL)
        {
            if (strcmp(user->username, identifier) == 0 || strcmp(user->account_number, identifier) == 0)
            {
                fprintf(stderr, "%s, %s\n", user->username, user->account_number);
                user->username = NULL;
                user->account_number = NULL;

                bank->accounts[i] = user;
                return 1;
            }
        }
    }

    return 0;
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

            if (user->username == NULL && user->account_number == NULL)
                continue;
            else
            {

                json_object_set_new(obj, "username", json_string(user->username));
                json_object_set_new(obj, "account_number", json_string(user->account_number));
            }

            json_array_append(results, obj);
            json_decref(obj);
        }

        return results;
    }
}

int callback_get_all_accounts(const struct _u_request *request, struct _u_response *response, void *user_data)
{
    Bank *bank = (Bank *)user_data;
    ulfius_set_json_body_response(response, 200, get_all_accounts(bank));

    return U_CALLBACK_CONTINUE;
}

int callback_add_account(const struct _u_request *request, struct _u_response *response, void *user_data)
{
    Bank *bank = (Bank *)user_data;
    json_t *req_obj = ulfius_get_json_body_request(request, NULL);

    char *username = json_string_value(json_object_get(req_obj, "username"));
    char *account_number = json_string_value(json_object_get(req_obj, "account_number"));

    Account *user = (Account *)calloc(1, sizeof(Account));

    user->account_number = account_number;
    user->username = username;

    int resp = add_account(bank, user);

    if (resp == 1)
        ulfius_set_string_body_response(response, 200, "{\"message\": \"ok\"}");
    return U_CALLBACK_CONTINUE;
}

int callback_delete_account(const struct _u_request *request, struct _u_response *response, void *user_data)
{
    Bank *bank = (Bank *)user_data;
    json_t *req_obj = ulfius_get_json_body_request(request, NULL);

    char *identifier = json_string_value(json_object_get(req_obj, "id"));

    int resp = delete_account(bank, identifier);

    if (resp == 1)
        ulfius_set_string_body_response(response, 200, "{\"message\": \"User deleted!\"}");

    return U_CALLBACK_CONTINUE;
}

#define FILE_OK 0
#define FILE_NOT_EXIST 1
#define FILE_TO_LARGE 2
#define FILE_READ_ERROR 3

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
/**
 * main function
 */
int main(void)
{
    struct _u_instance instance;

    Bank *bank = (Bank *)malloc(sizeof(Bank));

    if (bank == NULL)
    {
        fprintf(stderr, "Unable to allocate memory for bank\n");
        return (1);
    }

    bank->accounts = (Account **)malloc(sizeof(Account *));
    bank->size = 1;

    initialize_accounts(bank);

    if (bank->accounts == NULL)
    {
        fprintf(stderr, "Unable to allocate memory for accounts\n");
        return (1);
    }

    // Initialize instance with the port number
    if (ulfius_init_instance(&instance, PORT, NULL, NULL) != U_OK)
    {
        fprintf(stderr, "Error ulfius_init_instance, abort\n");
        return (1);
    }

    // Endpoint list declaration
    ulfius_add_endpoint_by_val(&instance, "GET", "/accounts", NULL, 0, &callback_get_all_accounts, bank);
    ulfius_add_endpoint_by_val(&instance, "POST", "/delete-account", NULL, 0, &callback_delete_account, bank);
    ulfius_add_endpoint_by_val(&instance, "POST", "/add-account", NULL, 0, &callback_add_account, bank);

    // add_account(_user);

    int err;
    size_t f_size;
    char *key, *cert;

    key = c_read_file("/home/kwabena/Downloads/ssl-example/key.pem", &err, &f_size);
    cert = c_read_file("/home/kwabena/Downloads/ssl-example/cert.pem", &err, &f_size);

    if (err)
    {
        // process error
    }
    else
    {
        // process data
        // Start the framework

        free(key);
        free(cert);
    }

    if (ulfius_start_framework(&instance) == U_OK)
    {
        printf("Start framework on port %d\n", instance.port);

        // Wait for the user to press <enter> on the console to quit the application
        getchar();
    }
    else
    {
        fprintf(stderr, "Error starting framework\n");
    }

    printf("End framework\n");

    ulfius_stop_framework(&instance);
    ulfius_clean_instance(&instance);

    return 0;
}