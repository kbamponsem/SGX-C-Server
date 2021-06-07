#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <malloc.h>

#define STATUS(a) (a != 0 ? "FAILED" : "SUCCESSFUL")

sgx_enclave_id_t enclave1_eid = 1; /* Enclave ID 1 */
sgx_enclave_id_t enclave2_eid = 2; /* Enclave ID 2 */

/* This method sets up Content-Type (Application/JSON) */
ngx_http_request_t *setup_content_type(ngx_http_request_t *r)
{
    r->headers_out.content_type.len = strlen("application/json") - 1;
    r->headers_out.content_type.data = (u_char *)"application/json";

    return r;
}

static char *ngx_get_all_accounts(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_add_account(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_delete_account(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_operation(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
ngx_buf_t *generate_output(ngx_http_request_t *r, int STATUS, void *data, char *request_type);
static ngx_int_t ngx_http_create_enclaves(ngx_conf_t *);

void ngx_add_account_func(ngx_http_request_t *r);
void ngx_delete_account_func(ngx_http_request_t *r);
void ngx_operation_func(ngx_http_request_t *r);

static ngx_command_t ngx_sgx_bank_module_commands[] = {
    {ngx_string("get_all_accounts"),
     NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
     ngx_get_all_accounts,
     0,
     0,
     NULL},
    {ngx_string("add_account"),
     NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
     ngx_add_account,
     0,
     0,
     NULL},
    {ngx_string("delete_account"),
     NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
     ngx_delete_account,
     0,
     0,
     NULL},
    {ngx_string("operation"),
     NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
     ngx_operation,
     0,
     0,
     NULL},
    ngx_null_command};

static ngx_http_module_t ngx_sgx_bank_module_ctx = {
    ngx_http_create_enclaves,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL};

ngx_module_t ngx_sgx_bank_module = {
    NGX_MODULE_V1,
    &ngx_sgx_bank_module_ctx,
    ngx_sgx_bank_module_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING};

static ngx_int_t ngx_http_create_enclaves(ngx_conf_t *cf)
{
    json_t *root = json_load_file("/home/kwabena/TaLoS/src/nginx-1.11.0/nginx_sgx_bank/enclaves_u.json", 0, NULL);

    const char *ENCLAVE1_TRUSTED = json_string_value(json_object_get(json_object_get(json_object_get(root, "Enclaves"), "1"), "trusted"));
    const char *ENCLAVE1_UNTRUSTED = json_string_value(json_object_get(json_object_get(json_object_get(root, "Enclaves"), "1"), "untrusted"));
    const char *ENCLAVE2_TRUSTED = json_string_value(json_object_get(json_object_get(json_object_get(root, "Enclaves"), "2"), "trusted"));
    const char *ENCLAVE2_UNTRUSTED = json_string_value(json_object_get(json_object_get(json_object_get(root, "Enclaves"), "2"), "untrusted"));

    int errors[2] = {1, 1};

    if (
        initialize_bank_enclave(ENCLAVE1_TRUSTED, ENCLAVE1_UNTRUSTED, &enclave1_eid) < 0)
    {
        errors[0] = 0;
    }

    if (
        initialize_bank_enclave(ENCLAVE2_TRUSTED, ENCLAVE2_UNTRUSTED, &enclave2_eid) < 0)
    {
        errors[1] = 0;
    }

    if (errors[0] != 1 || errors[1] != 1)
    {
        printf("Enclave Setup Failed!\n");
        return NGX_ERROR;
    }
    printf("Enclave Setup Successful!\n");
    return NGX_OK;
}