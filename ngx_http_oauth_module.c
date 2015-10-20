
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_crypt.h>


#define NGX_HTTP_OAUTH_BUF_SIZE  2048


typedef struct {
    ngx_str_t                 passwd;
} ngx_http_oauth_ctx_t;


typedef struct {
    ngx_http_complex_value_t  *realm;
    ngx_http_complex_value_t   user_file;
} ngx_http_oauth_loc_conf_t;


static ngx_int_t ngx_http_oauth_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_oauth_handler_check(ngx_http_request_t *r,
    ngx_str_t *realm, ngx_str_t *user_file);
static ngx_int_t ngx_http_oauth_handler_check_querystring(ngx_http_request_t *r,
    ngx_str_t *realm, ngx_str_t *user_file);
static ngx_int_t ngx_http_oauth_handler_check_cookie(ngx_http_request_t *r,
    ngx_str_t *realm, ngx_str_t *user_file);
static ngx_int_t
    ngx_http_oauth_handler_user_file(ngx_http_request_t *r,
    char *query_value, ngx_str_t *user_file);
static void ngx_http_oauth_close(ngx_file_t *file);
static void *ngx_http_oauth_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_oauth_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_oauth_init(ngx_conf_t *cf);
static char *ngx_http_oauth_user_file(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
/**
 * 以=为分隔符取vlaue
 */ 
static char* eq_query_name(ngx_http_request_t *r, char *str, char *name) {
    char *index = ngx_strchr(str, '=');
    if (index != NULL && index != str) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "eq_query_name found %s\n", "=");
        int query_name_len = index - str;
        char* query_name = malloc(query_name_len + 1);
        ngx_memzero(query_name, query_name_len + 1);
        ngx_memcpy(query_name, str, query_name_len);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "eq_query_name query_name:%s\n", query_name);

        int query_value_len = (str + ngx_strlen(str)) - index - 1;
        if (query_value_len == 0) {
            return NULL;
        }
        char* query_value = malloc(query_value_len + 1);
        ngx_memzero(query_value, query_value_len + 1);
        ngx_memcpy(query_value, index + 1, query_value_len);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "eq_query_name query_value:%s\n", query_value);

        int cmp = ngx_strcmp(name, query_name);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "eq_query_name cmp:%d\n", cmp);
        if (cmp == 0) {
            free(query_name);
            query_name = NULL;
            return query_value;
        } else {
            free(query_name);
            query_name = NULL;
            free(query_value);
            query_value = NULL;
        }
    }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "eq_query_name result:%d\n", 0);
    return NULL;
}

/**
 * 取cookie中指定的name
 */
static char* get_cookie(ngx_http_request_t *r, char* name)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "get_cookie cookie len:%d\n", r->headers_in.cookies.nelts);
    
    if (&r->headers_in.cookies) {
        //如果有cookie
        if (r->headers_in.cookies.nelts) {
            
            ngx_table_elt_t ** cookies = r->headers_in.cookies.elts;  
            
            ngx_uint_t i = 0;
            for (; i < r->headers_in.cookies.nelts; i++) {   
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "get_cookie Cookie key %s\n", cookies[i]->key.data);

                if (ngx_strcasecmp((u_char*)"Cookie", (u_char*)cookies[i]->key.data) == 0) {
                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "get_cookie Cookie line %s\n", cookies[i]->value.data);
                    
                    u_char *cookie_data = cookies[i]->value.data;
                    //如果cookie只有一对key value
                    if (ngx_strchr(cookie_data, ';') == NULL) {
                        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "get_cookie only one query:%s\n", cookie_data);
                        return eq_query_name(r, (char*)cookie_data, name);
                    } else {
						
						//复制querystring
						int cookie_line_len = cookies[i]->value.len + 1;
						char *cookie_line_str = (char*)malloc(cookie_line_len);
						ngx_memzero(cookie_line_str, cookie_line_len);
						ngx_memcpy(cookie_line_str, cookie_data, cookie_line_len -1 );
						
                        const char *token = "; ";
                        char *pch;
                        char *result = NULL;

                        for (pch = strtok (cookie_line_str, token); pch != NULL; pch = strtok (NULL, token)) {
                            result = eq_query_name(r, pch, name);
                            if (result != NULL) {
                                break;
                            }
                        }
						
						free(cookie_line_str);
						cookie_line_str = NULL;
						
                        return result;
                    }
                } 
                   
            } 
        }
        
    }
    return NULL;
}

/**
 * 取querystring
 */
static char* get_querystring(ngx_http_request_t *r, char* name)
{
    if (name == NULL || r->args.len == 0) {
        return NULL;
    }
	
	//复制querystring
	int query_str_len = r->args.len + 1;
	char *query_str = (char*)malloc(query_str_len);
	ngx_memzero(query_str, query_str_len);
	ngx_memcpy(query_str, r->args.data, r->args.len);

    if (ngx_strchr(query_str, '&') == NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_oauth only one query:%s\n", query_str);
        return eq_query_name(r, query_str, name);
    }

    char * pch;
    char *result = NULL;
    for (pch = strtok (query_str, "&"); pch != NULL; pch = strtok (NULL, "&")) {
        result = eq_query_name(r, pch, name);
        if (result != NULL) {
            break;
        }
    }
    
	free(query_str);
	query_str = NULL;
	
    return result;
}

static ngx_command_t  ngx_http_oauth_commands[] = {

    { ngx_string("oauth"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oauth_loc_conf_t, realm),
      NULL },

    { ngx_string("oauth_user_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_oauth_user_file,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oauth_loc_conf_t, user_file),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_oauth_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_oauth_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_oauth_create_loc_conf,   /* create location configuration */
    ngx_http_oauth_merge_loc_conf     /* merge location configuration */
};


ngx_module_t  ngx_http_oauth_module = {
    NGX_MODULE_V1,
    &ngx_http_oauth_module_ctx,       /* module context */
    ngx_http_oauth_commands,          /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_oauth_handler(ngx_http_request_t *r)
{
    ngx_str_t   realm, user_file;
    ngx_http_oauth_loc_conf_t  *alcf;


    alcf = ngx_http_get_module_loc_conf(r, ngx_http_oauth_module);

    if (alcf->realm == NULL || alcf->user_file.value.data == NULL) {
        return NGX_DECLINED;
    }

    if (ngx_http_complex_value(r, alcf->realm, &realm) != NGX_OK) {
        return NGX_ERROR;
    }

    if (realm.len == 3 && ngx_strncmp(realm.data, "off", 3) == 0) {
        return NGX_DECLINED;
    }

    if (ngx_http_complex_value(r, &alcf->user_file, &user_file) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_http_oauth_handler_check(r, &realm, &user_file);
}

static ngx_int_t
ngx_http_oauth_handler_check(ngx_http_request_t *r, ngx_str_t *realm, ngx_str_t *user_file)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_oauth_handler_check realm:%s\n", realm->data);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_oauth_handler_check user_file:%s\n", user_file->data);

    ngx_int_t http_code = ngx_http_oauth_handler_check_cookie(r, realm, user_file);

    if (http_code != NGX_OK) {
        http_code = ngx_http_oauth_handler_check_querystring(r, realm, user_file);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_oauth_handler_check result:%d\n", http_code);
    return http_code;
}

static ngx_int_t 
ngx_http_oauth_handler_check_querystring(ngx_http_request_t *r, ngx_str_t *realm, ngx_str_t *user_file)
{
    ngx_int_t http_code = NGX_HTTP_UNAUTHORIZED;
    //有query string
    if (r->args.len) {

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_oauth_handler_check_querystring request args:%s\n", r->args.data);

        char *oauth = get_querystring(r, (char*)realm->data);
        if (oauth != NULL) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_oauth_handler_check_querystring get_querystring result oauth:%s\n", oauth);

            http_code = ngx_http_oauth_handler_user_file(r, oauth, user_file);      

            free(oauth);
            oauth = NULL;
        }
    }
	
    return http_code;
}

static ngx_int_t 
ngx_http_oauth_handler_check_cookie(ngx_http_request_t *r, ngx_str_t *realm, ngx_str_t *user_file)
{
    ngx_int_t http_code = NGX_HTTP_UNAUTHORIZED;

    if (&r->headers_in.cookies) {
        //如果有cookie
        if (r->headers_in.cookies.nelts) {
            char *oauth = get_cookie(r, (char*)realm->data);
            if (oauth != NULL) {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_oauth_handler_check_cookie get_cookie result oauth:%s\n", oauth);

                http_code = ngx_http_oauth_handler_user_file(r, oauth, user_file);      

                free(oauth);
                oauth = NULL;
            }
        }
    }

    return http_code;
}    

static ngx_int_t 
ngx_http_oauth_handler_user_file(ngx_http_request_t *r,
    char *query_value, ngx_str_t *user_file) 
{
    ngx_fd_t    fd;
    ngx_file_t  file;
    
    fd = ngx_open_file(user_file->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);


    if (fd == NGX_INVALID_FILE) {

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      ngx_open_file_n " \"%s\" failed", user_file->data);

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memzero(&file, sizeof(ngx_file_t));

    file.fd = fd;
    file.name = *user_file;
    file.log = r->connection->log;

    ngx_int_t result_code = NGX_HTTP_UNAUTHORIZED;

    //read line and compare
    u_char buffer[NGX_HTTP_OAUTH_BUF_SIZE];
    int len = 0;
    int offset = 0;
    int i;
    int line_len = 0;
    while (NGX_ERROR != (len = ngx_read_file(&file, buffer, NGX_HTTP_OAUTH_BUF_SIZE, offset))) {

        if (len == 0) {
            break;
        }        

        for (i = 0; i < len; i++) {
            if (buffer[i] == LF || buffer[i] == CR ) {
                buffer[i] = '\0';
            }
        }

        line_len = ngx_strlen(buffer);
        if (line_len == 0) {
            offset += 1;
            ngx_memzero(&buffer, NGX_HTTP_OAUTH_BUF_SIZE);
            continue;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_oauth ngx_http_oauth_handler_user_file line:%s\n", buffer);

        if (ngx_strcmp(query_value, buffer) == 0) {
            result_code = NGX_OK;
            break;
        } else {
            offset += line_len;
            offset += 1;
        }
        ngx_memzero(&buffer, NGX_HTTP_OAUTH_BUF_SIZE);
    }

    ngx_http_oauth_close(&file);

    return result_code;
}

static void
ngx_http_oauth_close(ngx_file_t *file)
{
    if (ngx_close_file(file->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, file->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", file->name.data);
    }
}


static void *
ngx_http_oauth_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_oauth_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_oauth_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
ngx_http_oauth_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_oauth_loc_conf_t  *prev = parent;
    ngx_http_oauth_loc_conf_t  *conf = child;

    if (conf->realm == NULL) {
        conf->realm = prev->realm;
    }

    if (conf->user_file.value.data == NULL) {
        conf->user_file = prev->user_file;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_oauth_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_oauth_handler;

    return NGX_OK;
}


static char *
ngx_http_oauth_user_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_oauth_loc_conf_t *alcf = conf;

    ngx_str_t                         *value;
    ngx_http_compile_complex_value_t   ccv;

    if (alcf->user_file.value.data) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &alcf->user_file;
    ccv.zero = 1;
    ccv.conf_prefix = 1;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
