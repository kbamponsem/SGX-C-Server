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
    r->headers_out.content_type.len = strlen("application/json");
    r->headers_out.content_type.data = (u_char *)"application/json";

    return r;
}

static char *ngx_create_account(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_login(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_logout(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_receive_id_and_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_get_enclave_pub_keys(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_get_balance(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_delete_account(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_operation(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
ngx_buf_t *generate_output(ngx_http_request_t *r, int STATUS, void *data, char *request_type);
static ngx_int_t ngx_http_create_enclaves(ngx_conf_t *);

void ngx_create_account_func(ngx_http_request_t *r);
void ngx_delete_account_func(ngx_http_request_t *r);
void ngx_login_func(ngx_http_request_t *r);
void ngx_logout_func(ngx_http_request_t *r);
void ngx_operation_func(ngx_http_request_t *r);
void ngx_receive_id_and_key_func(ngx_http_request_t *r);
void ngx_get_balance_func(ngx_http_request_t *r);

ngx_buf_t *generate_output(ngx_http_request_t *r, int STATUS, void *data, char *request_type);

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

    printf("Enclave1 KEYS: %d\n", KEY1_STATUS);
    printf("Enclave1 KEYS: %d\n", KEY2_STATUS);

    if (KEY1_STATUS > 0 && KEY2_STATUS > 0)
        printf("Enclave Setup Successful!\n");

    return NGX_OK;
}
ngx_buf_t *generate_output(ngx_http_request_t *r, int STATUS, void *data, char *request_type)
{
    ngx_int_t rc;
    big_int *acccount_number = 0UL;
    if (data != NULL)
    {
        acccount_number = (big_int *)data;
    }

    json_t *response = json_object();

    json_object_set_new(response, "message", json_string(STATUS == 1 ? "SUCCESS" : "ERROR"));
    if (request_type != NULL)
    {
        if (strcmp(request_type, "/create-account") == 0 && STATUS == 1)
        {
            json_object_set_new(response, "account_number", json_integer(*acccount_number));
        }
    }
    else
        json_object_set_new(response, "data", json_string((char *)data));

    u_char *response_string = (u_char *)json_dumps(response, 0);
    size_t sz = strlen(response_string);
    ngx_buf_t *b = ngx_create_temp_buf(r->pool, NGX_OFF_T_LEN);

    b = ngx_create_temp_buf(r->pool, NGX_OFF_T_LEN);
    if (b == NULL)
    {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    b->pos = response_string;
    b->last = response_string + sz;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    r->headers_out.status = STATUS == 1 ? NGX_HTTP_OK : 203;
    r->headers_out.content_length_n = b->last - b->pos;

    rc = ngx_http_send_header(setup_content_type(r));

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
    {
        ngx_http_finalize_request(r, rc);
        return NULL;
    }

    return b;
}