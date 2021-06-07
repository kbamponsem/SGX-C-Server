#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <malloc.h>
#include "functions.h"
#include <jansson.h>
#include "ocall_defs.h"
#include <pthread.h>
#include "ngx_sgx_bank_module.h"

static ngx_int_t ngx_callback_get_all_accounts(ngx_http_request_t *r)
{
	char *users = (char *)calloc(1, sizeof(char));
	char *balances = (char *)calloc(1, sizeof(char));

	sgx_status_t user_ret = get_users(enclave1_eid, &users);
	sgx_status_t balance_ret = get_balances(enclave2_eid, &balances);

	json_t *response = json_object();
	json_object_set_new(response, "users", json_loads(users, 0, NULL));
	json_object_set_new(response, "balances", json_loads(balances, 0, NULL));

	u_char *all_accounts = (u_char *)json_dumps(response, 0);
	size_t sz = strlen(all_accounts);

	r->headers_out.status = NGX_HTTP_OK;
	ngx_http_send_header(setup_content_type(r));

	ngx_buf_t *b;
	ngx_chain_t out;

	b = ngx_create_temp_buf(r->pool, NGX_OFF_T_LEN);

	b->pos = all_accounts;
	b->last = all_accounts + sz;
	b->last_buf = (r == r->main) ? 1 : 0;
	b->last_in_chain = 1;

	out.buf = b;
	out.next = NULL;

	return ngx_http_output_filter(r, &out);
}

static ngx_int_t ngx_callback_add_account(ngx_http_request_t *r)
{
	ngx_int_t rc;

	rc = ngx_http_read_client_request_body(r, ngx_add_account_func);

	if (rc >= NGX_HTTP_SPECIAL_RESPONSE)
	{
		return rc;
	}

	return NGX_DONE;
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

	return NGX_DONE;
}

void ngx_operation_func(ngx_http_request_t *r)
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
	json_t *op = json_object();

	big_int account_number = json_integer_value(json_object_get(req_obj, "account_number"));
	const char *type = json_string_value(json_object_get(req_obj, "type"));
	float amount = (float)json_number_value(json_object_get(req_obj, "amount"));

	json_object_set_new(op, "type", json_string(type));
	json_object_set_new(op, "account_number", json_integer(account_number));
	json_object_set_new(op, "amount", json_real(amount));

	int RESULTS = 0;

	sgx_status_t ret = operation(enclave2_eid, &RESULTS, json_dumps(op, 0));

	out.buf = generate_output(r, RESULTS, NULL, NULL);
	out.next = NULL;

	rc = ngx_http_output_filter(r, &out);

	ngx_http_finalize_request(r, rc);
}

void ngx_add_account_func(ngx_http_request_t *r)
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

	json_t *user = json_object();
	json_t *balance = json_object();

	big_int acc_number = generate_account_number();

	json_object_set_new(user, "username", json_object_get(req_obj, "name"));
	json_object_set_new(user, "account_number", json_integer(acc_number));

	json_object_set_new(balance, "amount", json_object_get(req_obj, "amount"));
	json_object_set_new(balance, "account_number", json_integer(acc_number));

	char *user_string = json_dumps(user, 0);
	char *balance_string = json_dumps(balance, 0);

	int USER_RESULTS, BALANCE_RESULTS;

	sgx_status_t ret_user = add_user(enclave1_eid, &USER_RESULTS, user_string);

	sgx_status_t ret_balance = add_balance(enclave2_eid, &BALANCE_RESULTS, balance_string);

	out.buf = generate_output(r, USER_RESULTS & BALANCE_RESULTS, &acc_number, "/add");
	out.next = NULL;

	rc = ngx_http_output_filter(r, &out);

	ngx_http_finalize_request(r, rc);
}

void ngx_delete_account_func(ngx_http_request_t *r)
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

	json_t *account_number = json_object_get(req_obj, "account_number");

	json_t *response = json_object();
	json_object_set_new(response, "account_number", account_number);

	char *req_string = json_dumps(response, 0);
	int USER_RESULTS, BALANCE_RESULTS;
	sgx_status_t user_ret = delete_user(enclave1_eid, &USER_RESULTS, req_string);
	sgx_status_t balance_ret = delete_balance(enclave2_eid, &BALANCE_RESULTS, req_string);

	out.buf = generate_output(r, USER_RESULTS & BALANCE_RESULTS, NULL, NULL);
	out.next = NULL;

	rc = ngx_http_output_filter(r, &out);

	ngx_http_finalize_request(r, rc);
}

static char *ngx_get_all_accounts(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_core_loc_conf_t *clcf;
	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_callback_get_all_accounts;
	return NGX_CONF_OK;
}

static char *ngx_add_account(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_core_loc_conf_t *clcf;
	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_callback_add_account;
	return NGX_CONF_OK;
}

static char *ngx_delete_account(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_core_loc_conf_t *clcf;
	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_callback_delete_account;
	return NGX_CONF_OK;
}

static char *ngx_operation(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_core_loc_conf_t *clcf;
	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_callback_operation;
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
		if (strcmp(request_type, "/add") == 0 && STATUS == 1)
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


