#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <malloc.h>
#include <jansson.h>
#include <pthread.h>
#include <openssl/rsa.h>
#include "Include/functions.h"
#include "Include/ngx_sgx_bank_module.h"
#include "Include/ocall_defs.h"
#include "core/Include/bank_functions.h"

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

	rc = ngx_http_read_client_request_body(r, NULL
	);

	if (rc >= NGX_HTTP_SPECIAL_RESPONSE)
	{
		return rc;
	}

	return NGX_HTTP_CONTINUE;
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