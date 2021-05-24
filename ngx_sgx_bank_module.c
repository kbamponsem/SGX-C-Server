#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <malloc.h>
#include "functions.h"
#include <jansson.h>

/* Content-Type */
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

void ngx_add_account_func(ngx_http_request_t *r);
void ngx_delete_account_func(ngx_http_request_t *r);
void ngx_operation_func(ngx_http_request_t *r);

static Bank *bank = NULL;
static All_Users *all_users = NULL;
static All_Balances *all_balances = NULL;

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
	NULL,
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

static ngx_int_t ngx_callback_get_all_accounts(ngx_http_request_t *r)
{
	const json_t *results = get_all_accounts(&all_users, &all_balances);

	u_char *all_accounts = (u_char *)json_dumps(results, 0);
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

	// show_accounts(bank);

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

	big_int account_number = json_integer_value(json_object_get(req_obj, "account_number"));
	const char *type = json_string_value(json_object_get(req_obj, "type"));
	float amount = (float)json_number_value(json_object_get(req_obj, "amount"));

	int RESULTS = operation(&all_balances, account_number, amount, type);

	out.buf = generate_output(r, RESULTS, NULL, NULL);
	out.next = NULL;

	rc = ngx_http_output_filter(r, &out);

	ngx_http_finalize_request(r, rc);
}

void print_u_char(u_char *buf)
{
	size_t len = strlen(buf);

	fprintf(stderr, " [ ");
	for (size_t i = 0; i < len; i++)
	{
		fprintf(stderr, "%d ", buf[i]);
	}
	fprintf(stderr, "]\n ");
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

	json_t *name = json_object_get(req_obj, "name");
	json_t *amount = json_object_get(req_obj, "amount");

	fprintf(stderr, "Name: %s\n", json_string_value(name));
	fprintf(stderr, "Amount: %0.2f\n", json_real_value(amount));

	size_t acc_number = generate_account_number();

	Account_B *balance = (Account_B *)calloc(1, sizeof(Account_B));
	Account_U *user = (Account_U *)calloc(1, sizeof(Account_U));

	user->username = json_string_value(name);
	user->account_number = acc_number;
	balance->balance = (float)json_real_value(amount);
	balance->account_number = acc_number;

	int RESULTS = add_account(&all_users, &all_balances, user, balance);

	out.buf = generate_output(r, RESULTS, &acc_number, "/add");
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

	big_int account_number_value = json_integer_value(account_number);

	fprintf(stderr, "Account Number: %lld\n", account_number_value);

	int RESULTS = delete_account(&all_users, &all_balances, json_integer_value(account_number));

	json_t *response = json_object();

	json_object_set_new(response, "message", json_string(RESULTS == 1 ? "User deleted successfully!" : "User not found!"));

	out.buf = generate_output(r, RESULTS, NULL, NULL);
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