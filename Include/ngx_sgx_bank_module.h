#ifndef NGX_SGX_BANK_MODULE_H__
#define NGX_SGX_BANK_MODULE_H__

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <malloc.h>

#include <sgx_eid.h>

#define STATUS(a) (a != 0 ? "FAILED" : "SUCCESSFUL")

sgx_enclave_id_t enclave1_eid = 1; /* Enclave ID 1 */
sgx_enclave_id_t enclave2_eid = 2; /* Enclave ID 2 */

/* This method sets up Content-Type (Application/JSON) */

static char *ngx_create_account(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_login(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_logout(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_receive_id_and_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_get_enclave_pub_keys(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_get_balance(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_delete_account(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_operation(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_create_enclaves(ngx_conf_t *);

static ngx_command_t ngx_sgx_bank_module_commands[] = {
    {ngx_string("get_enclave_pub_keys"),
     NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
     ngx_get_enclave_pub_keys,
     0,
     0,
     NULL},
    {ngx_string("create_account"),
     NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
     ngx_create_account,
     0,
     0,
     NULL},
    {ngx_string("login"),
     NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
     ngx_login,
     0,
     0,
     NULL},
    {ngx_string("id_and_key"),
     NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
     ngx_receive_id_and_key,
     0,
     0,
     NULL},
    {ngx_string("logout"),
     NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
     ngx_logout,
     0,
     0,
     NULL},
    {ngx_string("get_balance"),
     NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
     ngx_get_balance,
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

RSA *create_RSA(char *pub_key)
{
    RSA *r = RSA_new();
    BIO *bio = BIO_new_mem_buf(pub_key, -1);
    r = PEM_read_bio_RSA_PUBKEY(bio, &r, NULL, NULL);
    return r;
}

char *public_encrypt(char *public_key, char *raw_text)
{
    char *message = (char *)calloc(4098, sizeof(char));
    char *encrypted = (char *)calloc(4098, sizeof(char));

    strcpy(message, raw_text);
    RSA_public_encrypt(strlen(message), message, encrypted, create_RSA(public_key), RSA_PKCS1_PADDING);

    return encrypted;
}

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

    int KEY1_STATUS, KEY2_STATUS;
    printf("-- GEN KEYS --\n");
    sgx_status_t ret;
    ret = enclave1_generate_keys(enclave1_eid, &KEY1_STATUS);
    ret = enclave2_generate_keys(enclave2_eid, &KEY2_STATUS);
    
    if (KEY1_STATUS > 0 && KEY2_STATUS > 0)
    {
        printf("Initializing Enclave 1...\n");
        printf("Initializing Enclave 2...\n");
        printf("Enclave Setup Successful!\n");
    }

    return NGX_OK;
}
#endif