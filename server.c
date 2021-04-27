#include <stdio.h>
#include <ulfius.h>
#include <jansson.h>
#include "endpoints.h"

void initialize_accounts(Bank *bank);

void show_accounts(Bank *bank);

int add_account(Bank *bank, Account *user);

int delete_account(Bank *bank, size_t identifier);

char *c_read_file(const char *f_name, int *err, size_t *f_size);

int main(int argc, char **argv)
{

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

    // Sever setup
    struct _u_instance instance;
    int PORT = atoi(argv[1]);

    // Initialize instance with the port number
    if (ulfius_init_instance(&instance, PORT, NULL, NULL) != U_OK)
    {
        fprintf(stderr, "Error ulfius_init_instance, abort\n");
        return (1);
    }

    // Endpoint list declaration
    ulfius_add_endpoint_list(&instance, setup_routes(bank));

    // Start the framework
    if (ulfius_start_framework(&instance) == U_OK)
    {
        printf("Start framework on port %d\n", instance.port);
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