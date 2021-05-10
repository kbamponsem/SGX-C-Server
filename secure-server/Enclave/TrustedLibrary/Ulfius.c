#include <stdio.h>
#include <stdlib.h>
#include <ulfius.h>

#include "../Enclave.h"

#include "Enclave_t.h"


void ecall_create_server(void)
{
    struct _u_instance instance;
    if (ulfius_init_instance(&instance, 8080, NULL, NULL) != U_OK)
    {
        fprintf(stderr, "Error ulfius_init_instance, abort\n");
        return (1);
    }

    // Endpoint list declaration
    ulfius_add_endpoint_by_val(&instance, "GET", "/", NULL, 0, NULL, NULL);

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
}