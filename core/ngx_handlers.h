#include <ngx_core.h>
#include <ngx_http.h>

static char *ngx_create_account(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_login(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_logout(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_receive_id_and_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_get_enclave_pub_keys(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_get_balance(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_delete_account(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_operation(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);