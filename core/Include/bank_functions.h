#ifndef BANK_FUNCTIONS_H__
#define BANK_FUNCTIONS_H__

#include <ngx_core.h>
#include <ngx_http.h>

void ngx_create_account_func(ngx_http_request_t *r);
void ngx_login_func(ngx_http_request_t *r);
void ngx_get_balance_func(ngx_http_request_t *r);
void ngx_logout_func(ngx_http_request_t *r);
void ngx_receive_id_and_key_func(ngx_http_request_t *r);
ngx_http_request_t *setup_content_type(ngx_http_request_t *r);

ngx_buf_t *generate_output(ngx_http_request_t *r, int STATUS, void *data, char *request_type);

#endif