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

static ngx_int_t ngx_callback_logout(ngx_http_request_t *r)
{
	ngx_int_t rc;

	rc = ngx_http_read_client_request_body(r, ngx_logout_func);

	if (rc >= NGX_HTTP_SPECIAL_RESPONSE)
	{
		return rc;
	}

	return NGX_DONE;
}

static ngx_int_t ngx_callback_get_enclave_pub_keys(ngx_http_request_t *r)
{

	char *enclave1_pub_key = (char *)calloc(2048, sizeof(char));
	char *enclave2_pub_key = (char *)calloc(2048, sizeof(char));

	sgx_status_t ret = enclave1_get_pub_key(enclave1_eid, enclave1_pub_key);
	ret = enclave2_get_pub_key(enclave2_eid, enclave2_pub_key);

	r->headers_out.status = NGX_HTTP_OK;
	ngx_http_send_header(setup_content_type(r));

	json_t *response = json_object();

	json_object_set_new(response, "enclave1_pub_key", json_string(enclave1_pub_key));
	json_object_set_new(response, "enclave2_pub_key", json_string(enclave2_pub_key));

	int stat;

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
	return ngx_http_output_filter(r, &out);
}

static ngx_int_t ngx_callback_get_balance(ngx_http_request_t *r)
{
	ngx_int_t rc;

	rc = ngx_http_read_client_request_body(r, ngx_get_balance_func);

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

void ngx_get_balance_func(ngx_http_request_t *r)
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

	int RESULTS = 0;
	char *balance_string = (char *)calloc(2048, sizeof(char));

	sgx_status_t ret = get_balance(enclave2_eid, &RESULTS, account_number, balance_string);

	out.buf = generate_output(r, RESULTS, balance_string, NULL);
	out.next = NULL;

	rc = ngx_http_output_filter(r, &out);

	ngx_http_finalize_request(r, rc);
}

void ngx_logout_func(ngx_http_request_t *r)
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

	big_int id = json_number_value(json_object_get(req_obj, "id"));

	int RESULTS;

	sgx_status_t ret = remove_session_id(enclave1_eid, &RESULTS, id);

	out.buf = generate_output(r, RESULTS, NULL, NULL);
	out.next = NULL;

	rc = ngx_http_output_filter(r, &out);

	ngx_http_finalize_request(r, rc);
}
void string2hexString(char *input, char *output)
{
	int loop;
	int i;

	i = 0;
	loop = 0;

	while (input[loop] != '\0')
	{
		sprintf((char *)(output + i), "%02X", input[loop]);
		loop += 1;
		i += 2;
	}
	// insert NULL at the end of the output string
	output[i++] = '\0';
}
void ngx_receive_id_and_key_func(ngx_http_request_t *r)
{
	ngx_int_t rc;
	ngx_chain_t out;
	int RESULTS = 0;

	if (r->request_body == NULL)
	{
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	char *req_body = (char *)r->request_body->bufs->buf->pos;

	json_t *req_obj = json_loads(req_body, 0, NULL);

	big_int account_number = json_number_value(json_object_get(req_obj, "account_number"));
	char *enc1_symmetric_key = (char *)json_string_value(json_object_get(req_obj, "enclave1_symmetric_key"));

	char *base64_string = base64_decode(enc1_symmetric_key);
	char *hex_string = malloc(strlen(base64_string) * sizeof(char));

	string2hexString(base64_string, hex_string);

	// printf("Account number: %lld\nEncoded key: %s\nDecoded key: %s\n", account_number, enc1_symmetric_key, hex_string);
	if (hex_string != NULL)
	{
		sgx_status_t ret = enclave1_create_session(enclave1_eid, &RESULTS, account_number, hex_string);
	}
	// {
	// 	// ret = enclave2_create_session(enclave2_eid, &RESULTS, account_number, enc2_symmetric_key);
	// }

	out.buf = generate_output(r, 1, NULL, NULL);
	out.next = NULL;

	rc = ngx_http_output_filter(r, &out);

	ngx_http_finalize_request(r, rc);
}
static char *ngx_get_enclave_pub_keys(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_core_loc_conf_t *clcf;
	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_callback_get_enclave_pub_keys;
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
static char *ngx_get_balance(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_core_loc_conf_t *clcf;
	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_callback_get_balance;
	return NGX_CONF_OK;
}

static char *ngx_logout(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_core_loc_conf_t *clcf;
	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_callback_logout;
	return NGX_CONF_OK;
}
