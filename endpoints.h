#include <ulfius.h>
#include <jansson.h>
#include "functions.h"

int callback_get_all_accounts(const struct _u_request *request, struct _u_response *response, void *user_data)
{
    Bank *bank = (Bank *)user_data;
    ulfius_set_json_body_response(response, 200, get_all_accounts(bank));

    return U_CALLBACK_CONTINUE;
}

int callback_delete_account(const struct _u_request *request, struct _u_response *response, void *user_data)
{
    Bank *bank = (Bank *)user_data;
    json_t *req_obj = ulfius_get_json_body_request(request, NULL);

    size_t identifier = json_integer_value(json_object_get(req_obj, "id"));

    int resp = delete_account(bank, identifier);

    if (resp == 1)
        ulfius_set_string_body_response(response, 200, "{\"message\": \"User deleted!\"}");
    else
        ulfius_set_string_body_response(response, 203, "{\"message\": \"User not found!\"}");

    return U_CALLBACK_CONTINUE;
}

int callback_add_account(const struct _u_request *request, struct _u_response *response, void *user_data)
{
    Bank *bank = (Bank *)user_data;
    json_t *req_obj = ulfius_get_json_body_request(request, NULL);

    const char *username = json_string_value(json_object_get(req_obj, "username"));
    float balance = json_number_value(json_object_get(req_obj, "balance"));

    Account *user = (Account *)calloc(1, sizeof(Account));

    user->username = username;
    user->balance = balance;
    user->account_number = generate_account_number();

    int resp = add_account(bank, user);

    if (resp == 1)
        ulfius_set_string_body_response(response, 200, "{\"message\": \"ok\"}");
    return U_CALLBACK_CONTINUE;
}

int callback_withdraw(const struct _u_request *request, struct _u_response *response, void *user_data)
{
    Bank *bank = (Bank *)user_data;
    json_t *req_obj = ulfius_get_json_body_request(request, NULL);

    size_t account_number = json_integer_value(json_object_get(req_obj, "account_number"));
    float amount = json_real_value(json_object_get(req_obj, "amount"));

    if (operation(bank, account_number, amount, "WITHDRAW") == 1)
        ulfius_set_string_body_response(response, 200, "{\"message\": \"ok\"}");

    return U_CALLBACK_CONTINUE;
}

int callback_deposit(const struct _u_request *request, struct _u_response *response, void *user_data)
{
    Bank *bank = (Bank *)user_data;
    json_t *req_obj = ulfius_get_json_body_request(request, NULL);

    size_t account_number = json_integer_value(json_object_get(req_obj, "account_number"));
    float amount = json_real_value(json_object_get(req_obj, "amount"));

    if (operation(bank, account_number, amount, "DEPOSIT") == 1)
        ulfius_set_string_body_response(response, 200, "{\"message\": \"ok\"}");

    return U_CALLBACK_CONTINUE;
}

struct _u_endpoint* create_route(   char* http_method,   
                                    unsigned int priority, 
                                    int (*callback_function)(const struct _u_request *request, struct _u_response *response, void *user_data),
                                    char* url_format,
                                    char* url_prefix,
                                    void* user_data
                                )
{
    struct _u_endpoint *endpoint = (struct _u_endpoint *)calloc(1, sizeof(struct _u_endpoint));
    endpoint->http_method = http_method;
    endpoint->priority = priority;
    endpoint->callback_function = callback_function;
    endpoint->url_format = url_format;
    endpoint->url_prefix = url_prefix;
    endpoint->user_data = user_data;

    return endpoint;
}

const struct _u_endpoint **setup_routes(void *data)
{
    const struct _u_endpoint **endpoints = (const struct _u_endpoint **)malloc(6 * sizeof(struct _u_endpoint *));

    endpoints[0] = create_route("GET", 0, callback_get_all_accounts, NULL, "/accounts", (Bank*) data);
    endpoints[1] = create_route("POST", 0, callback_add_account, NULL, "/add-account", (Bank*) data);
    endpoints[2] = create_route("POST", 0, callback_delete_account, NULL, "/delete-account", (Bank*) data);
    endpoints[3] = create_route("POST", 0, callback_withdraw, NULL, "/withdraw", (Bank*) data);
    endpoints[4] = create_route("POST", 0, callback_deposit, NULL, "/deposit", (Bank*) data);

    return endpoints;
}