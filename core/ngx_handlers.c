#ifndef NGX_HANDLERS_H__
#define NGX_HANDLERS_H__
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_handlers.h"

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

#endif