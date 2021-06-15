#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <malloc.h>
#include "functions.h"
#include <jansson.h>
#include "ocall_defs.h"
#include <pthread.h>
#include "ngx_sgx_bank_module.h"
#include <openssl/rsa.h>

static ngx_int_t ngx_callback_create_account(ngx_http_request_t *r)
{
	ngx_int_t rc;

	rc = ngx_http_read_client_request_body(r, ngx_create_account_func);

	if (rc >= NGX_HTTP_SPECIAL_RESPONSE)
	{
		return rc;
	}

	return NGX_DONE;
}

static ngx_int_t ngx_callback_receive_id_and_key(ngx_http_request_t *r)
{
	ngx_int_t rc;

	rc = ngx_http_read_client_request_body(r, ngx_receive_id_and_key_func);

	if (rc >= NGX_HTTP_SPECIAL_RESPONSE)
	{
		return rc;
	}

	return NGX_DONE;
}

static ngx_int_t ngx_callback_login(ngx_http_request_t *r)
{
	ngx_int_t rc;

	rc = ngx_http_read_client_request_body(r, ngx_login_func);

	if (rc >= NGX_HTTP_SPECIAL_RESPONSE)
	{
		return rc;
	}

	return NGX_DONE;
}

char *public_encrypt(char *public_key, char *raw_text)
{
	char *message = (char *)calloc(4098, sizeof(char));
	char *encrypted = (char *)calloc(4098, sizeof(char));

	strcpy(message, raw_text);
	RSA_public_encrypt(strlen(message), message, encrypted, create_RSA(public_key), RSA_PKCS1_PADDING);

	return encrypted;
}
static ngx_int_t ngx_callback_get_enclave1_pub_key(ngx_http_request_t *r)
{

	char *enclave1_pub_key = (char *)calloc(2048, sizeof(char));

	sgx_status_t ret = get_pub_key(enclave1_eid, enclave1_pub_key);

	r->headers_out.status = NGX_HTTP_OK;
	ngx_http_send_header(setup_content_type(r));

	json_t *response = json_object();

	json_object_set_new(response, "enclave_pub_key", json_string(enclave1_pub_key));

	/*
		Test pubkey decryption
	*/
	char *message = (char *)calloc(4098, sizeof(char));
	char *encrypted = (char *)calloc(4098, sizeof(char));
	char *decrypted = (char *)calloc(4098, sizeof(char));

	int stat;
	// strcpy(message, "KEY");
	// int stat = RSA_public_encrypt(strlen(message), message, encrypted, create_RSA(enclave1_pub_key), RSA_PKCS1_PADDING);
	// printf("STAT: %d\n", stat);

	// print_string(message);
	// print_string(encrypted);

	encrypted = public_encrypt(enclave1_pub_key, "Kwabena");
	print_string(encrypted);

	// printf("STAT: %d\n", stat);

	u_char *response_string = (u_char *)json_dumps(response, 0);

	size_t sz = strlen(response_string);

	ngx_buf_t *b;
	ngx_chain_t out;

	b = ngx_create_temp_buf(r->pool, NGX_OFF_T_LEN);
	if (b == NULL)
	{
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return NGX_ERROR;
	}

	b->pos = response_string;
	b->last = response_string + sz;
	b->last_buf = (r == r->main) ? 1 : 0;
	b->last_in_chain = 1;

	out.buf = b;
	out.next = NULL;
	free(message);
	free(encrypted);
	free(enclave1_pub_key);
	return ngx_http_output_filter(r, &out);
}
static ngx_int_t ngx_callback_delete_account(ngx_http_request_t *r)
{
	ngx_int_t rc;

	rc = ngx_http_read_client_request_body(r, ngx_delete_account_func);

	if (rc >= NGX_HTTP_SPECIAL_RESPONSE)
	{
		return rc;
	}

	return NGX_DONE;
}

static ngx_int_t ngx_callback_operation(ngx_http_request_t *r)
{
	ngx_int_t rc;

	rc = ngx_http_read_client_request_body(r, ngx_operation_func);

	if (rc >= NGX_HTTP_SPECIAL_RESPONSE)
	{
		return rc;
	}

	return NGX_HTTP_CONTINUE;
}

void ngx_create_account_func(ngx_http_request_t *r)
{
	ngx_int_t rc;
	ngx_chain_t out;

	if (r->request_body == NULL)
	{
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	char *req_body = trim_string((char *)r->request_body->bufs->buf->pos);

	json_t *req_obj = json_loads(req_body, 0, NULL);

	char *username = (char *)json_string_value(json_object_get(req_obj, "username"));
	char *password = (char *)json_string_value(json_object_get(req_obj, "password"));

	big_int acc_number = generate_account_number();

	int USER_RESULTS;

	sgx_status_t ret_user = create_account(enclave1_eid, &USER_RESULTS, username, password, acc_number);

	out.buf = generate_output(r, USER_RESULTS, &acc_number, "/create-account");
	out.next = NULL;

	rc = ngx_http_output_filter(r, &out);

	ngx_http_finalize_request(r, rc);
}

void ngx_login_func(ngx_http_request_t *r)
{
	ngx_int_t rc;
	ngx_chain_t out;

	if (r->request_body == NULL)
	{
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	char *req_body = trim_string((char *)r->request_body->bufs->buf->pos);

	json_t *req_obj = json_loads(req_body, 0, NULL);

	big_int account_number = json_number_value(json_object_get(req_obj, "account_number"));
	char *password = (char *)json_string_value(json_object_get(req_obj, "password"));

	int RESULTS;

	sgx_status_t ret_user = login(enclave1_eid, &RESULTS, account_number, password);

	out.buf = generate_output(r, RESULTS, NULL, NULL);
	out.next = NULL;

	rc = ngx_http_output_filter(r, &out);

	ngx_http_finalize_request(r, rc);
}

void ngx_receive_id_and_key_func(ngx_http_request_t *r)
{
	ngx_int_t rc;
	ngx_chain_t out;

	if (r->request_body == NULL)
	{
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	char *req_body = trim_string((char *)r->request_body->bufs->buf->pos);

	json_t *req_obj = json_loads(req_body, 0, NULL);

	big_int account_number = json_number_value(json_object_get(req_obj, "account_number"));
	char *symmetric_key = (char *)json_string_value(json_object_get(req_obj, "symmetric_key"));
	char *enclave1_pub_key = (char *)calloc(2048, sizeof(char));

	sgx_status_t ret = get_pub_key(enclave1_eid, enclave1_pub_key);
	char *encrypted_symmetric_key = public_encrypt(enclave1_pub_key, symmetric_key);

	int RESULTS = 0;

	ret = create_session(enclave1_eid, &RESULTS, account_number, encrypted_symmetric_key);
	char *session_id = (char *)calloc(2048, sizeof(char));

	ret = get_user_session_id(enclave1_eid, account_number, session_id);

	print_string(session_id);
	out.buf = generate_output(r, RESULTS, NULL, NULL);
	out.next = NULL;

	rc = ngx_http_output_filter(r, &out);

	ngx_http_finalize_request(r, rc);
}
static char *ngx_get_enclave1_pub_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_core_loc_conf_t *clcf;
	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_callback_get_enclave1_pub_key;
	return NGX_CONF_OK;
}

static char *ngx_receive_id_and_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_core_loc_conf_t *clcf;
	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_callback_receive_id_and_key;
	return NGX_CONF_OK;
}
static char *ngx_create_account(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_core_loc_conf_t *clcf;
	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_callback_create_account;
	return NGX_CONF_OK;
}

static char *ngx_login(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_core_loc_conf_t *clcf;
	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_callback_login;
	return NGX_CONF_OK;
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
		if (strcmp(request_type, "/create-account") == 0 && STATUS == 1)
			json_object_set_new(response, "account_number", json_integer(*acccount_number));

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
