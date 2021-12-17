#include <ngx_core.h>
#include <ngx_http.h>
#include <jansson.h>
#include "../Include/types.h"
#include "Include/bank_functions.h"
#include "../Include/utils.h"
#include <sgx_eid.h>   /* sgx_enclave_id_t */

#include "../nginx_sgx_bank/Enclaves_u/Enclave1/Untrusted/UserEnclave_u.h"

extern size_t generate_account_number();
extern sgx_enclave_id_t enclave1_eid;

ngx_http_request_t *setup_content_type(ngx_http_request_t *r)
{
	r->headers_out.content_type.len = strlen("application/json");
	r->headers_out.content_type.data = (u_char *)"application/json";

	return r;
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

	int USER_RESULTS = -1;

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

	int RESULTS = -1;

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

	int RESULTS = -1;
	char *balance_string = (char *)calloc(2048, sizeof(char));

	// sgx_status_t ret = get_balance(enclave2_eid, &RESULTS, account_number, balance_string);

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

	int RESULTS = -1;

	// sgx_status_t ret = remove_session_id(enclave1_eid, &RESULTS, id);

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

	out.buf = generate_output(r, -1, NULL, NULL);
	out.next = NULL;

	rc = ngx_http_output_filter(r, &out);

	ngx_http_finalize_request(r, rc);
}