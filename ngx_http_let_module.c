/******************************************************************************
Copyright (c) 2011, Roman Arutyunyan (arut@qip.ru)
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, 
are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice, 
      this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice, 
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR 
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
OF SUCH DAMAGE.
*******************************************************************************/

/*
   NGINX module providing arithmetic operations support
*/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stdlib.h>
#include <time.h>
#include "let.h"

#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

static char* ngx_http_let_let(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* Module commands */
static ngx_command_t ngx_http_let_commands[] = {

    {	ngx_string("let"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
        ngx_http_let_let,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    ngx_null_command
};

/* Module context */
static ngx_http_module_t ngx_http_let_module_ctx = {

    NULL,                              /* preconfiguration */
    NULL,                              /* postconfiguration */
    NULL,                              /* create main configuration */
    NULL,                              /* init main configuration */
    NULL,                              /* create server configuration */
    NULL,                              /* merge server configuration */
    NULL,                              /* create location configuration */
    NULL                               /* merge location configuration */
};

/* Module */
ngx_module_t ngx_http_let_module = {

    NGX_MODULE_V1,
    &ngx_http_let_module_ctx,          /* module context */
    ngx_http_let_commands,             /* module directives */
    NGX_HTTP_MODULE,                   /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    NULL,                              /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_let_toi(ngx_str_t* s) 
{
    return (s->len > 2 && s->data[0] == '0' && s->data[1] == 'x')

        ? ngx_hextoi(s->data + 2, s->len - 2)

        : ngx_atoi(s->data, s->len);
}

/* Function engine */
static ngx_int_t ngx_let_func_rand(ngx_http_request_t *r, ngx_str_t *ret)
{
    ret->len = 32;
    ret->data = ngx_palloc(r->pool, ret->len);

    ret->len = ngx_snprintf(ret->data, ret->len, "%d", rand()) - ret->data;

    return NGX_OK;
}

#define NGX_LET_HASHFUNC(fun, name, hashlen) \
static ngx_int_t ngx_let_func_##name(ngx_http_request_t *r, \
        ngx_str_t *arg, ngx_str_t *ret) \
{ \
    u_char md[hashlen]; \
    unsigned n; \
    u_char *s; \
    static u_char hex[] = "0123456789abcdef"; \
\
    ret->len = sizeof(md) * 2; \
    ret->data = ngx_palloc(r->pool, ret->len); \
\
    fun(arg->data, arg->len, md); \
\
    for(n = 0, s = ret->data; n < sizeof(md); ++n) { \
        *s++ = hex[(md[n] >> 4) & 0x0f]; \
        *s++ = hex[md[n] & 0x0f]; \
    } \
\
    return NGX_OK; \
}

NGX_LET_HASHFUNC(MD4, md4, 16)
NGX_LET_HASHFUNC(MD5, md5, 16)

NGX_LET_HASHFUNC(SHA1,   sha1,   20)
NGX_LET_HASHFUNC(SHA224, sha224, 28)
NGX_LET_HASHFUNC(SHA256, sha256, 32)
NGX_LET_HASHFUNC(SHA384, sha384, 48)
NGX_LET_HASHFUNC(SHA512, sha512, 64)

NGX_LET_HASHFUNC(RIPEMD160, ripemd160, 20)

static ngx_int_t ngx_let_func_len(ngx_http_request_t *r, 
        ngx_str_t *str, ngx_str_t *ret)
{
    ret->len = 32;
    ret->data = ngx_palloc(r->pool, ret->len);

    ret->len = ngx_snprintf(ret->data, ret->len, "%d", str->len) - ret->data;

    return NGX_OK;
}

static ngx_int_t ngx_let_func_lower(ngx_http_request_t *r,
        ngx_str_t *str, ngx_str_t *ret)
{
    ngx_uint_t i;

    ret->len = str->len;
    ret->data = ngx_palloc(r->pool, ret->len);
    if (ret->data == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < str->len; i++) {
        ret->data[i] = ngx_tolower(str->data[i]);
    }

    return NGX_OK;
}

static ngx_int_t ngx_let_func_upper(ngx_http_request_t *r,
        ngx_str_t *str, ngx_str_t *ret)
{
    ngx_uint_t i;

    ret->len = str->len;
    ret->data = ngx_palloc(r->pool, ret->len);
    if (ret->data == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < str->len; i++) {
        ret->data[i] = ngx_toupper(str->data[i]);
    }

    return NGX_OK;
}

#define NGX_LET_ICMPFUNC(name, op) \
static ngx_int_t ngx_let_func_##name(ngx_http_request_t *r, \
        ngx_str_t *a1, ngx_str_t *a2, ngx_str_t *ret) \
{ \
    ngx_int_t v1, v2; \
    ret->len = 32; \
    ret->data = ngx_palloc(r->pool, ret->len); \
\
    v1 = ngx_atoi(a1->data, a1->len); \
    v2 = ngx_atoi(a2->data, a2->len); \
\
    ret->len = ngx_snprintf(ret->data, ret->len, "%d", \
        v1 op v2 ? v1 : v2) - ret->data; \
\
    return NGX_OK; \
}

NGX_LET_ICMPFUNC(min, <)
NGX_LET_ICMPFUNC(max, >)

static ngx_int_t ngx_let_func_substr(ngx_http_request_t *r, 
        ngx_str_t *str, ngx_str_t *offset,
        ngx_str_t *length, ngx_str_t *ret)
{
    ngx_int_t offs, len;

    *ret = *str;

    offs = ngx_atoi(offset->data, offset->len);
    len = ngx_atoi(length->data, length->len);

    if (offs >= (ngx_int_t)ret->len) {
        ret->len = 0;
        return NGX_OK;
    }

    ret->data += offs;

    if (!len || offs + len >= (ngx_int_t)ret->len)
        ret->len -= offs;
    else
        ret->len = len;

    return NGX_OK;
}

static ngx_int_t ngx_let_func_position(ngx_http_request_t *r,
        ngx_str_t *s, ngx_str_t *s1, ngx_str_t *ret)
{
    u_char *p;
    u_char *last;

    ret->len = NGX_OFF_T_LEN;
    ret->data = ngx_palloc(r->pool, ret->len);
    if (ret->data == NULL) {
        return NGX_ERROR;
    }

    if (s == NULL || s1 == NULL || s->len == 0 || s1->len == 0) {
        ret->len = 0;
        return NGX_OK;
    }

    last = s->data + s->len - s1->len;

    for (p = s->data; p <= last; p++) {
        if (ngx_strncmp(p, s1->data, s1->len) == 0) {
            ngx_int_t pos = p - s->data;
            ret->len = ngx_sprintf(ret->data, "%d", pos) - ret->data;
            return NGX_OK;
        }
    }

    ret->len = 0;
    return NGX_OK;
}

static ngx_int_t ngx_let_func_trim(ngx_http_request_t *r,
        ngx_str_t *str, ngx_str_t *ret)
{
    u_char *start, *end;
    ngx_uint_t i;

    start = str->data;
    end = str->data + str->len - 1;

    while (start <= end && (*start == ' ' || *start == '\t' || *start == '\n' || *start == '\r')) {
        start++;
    }

    while (end >= start && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) {
        end--;
    }

    ret->len = end >= start ? (ngx_uint_t)(end - start + 1) : 0;
    ret->data = ngx_palloc(r->pool, ret->len);
    if (ret->data == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < ret->len; i++) {
        ret->data[i] = start[i];
    }

    return NGX_OK;
}

static ngx_int_t ngx_let_func_ltrim(ngx_http_request_t *r,
        ngx_str_t *str, ngx_str_t *ret)
{
    u_char *start;
    ngx_uint_t i;

    start = str->data;

    while (start < str->data + str->len && (*start == ' ' || *start == '\t' || *start == '\n' || *start == '\r')) {
        start++;
    }

    ret->len = str->len - (start - str->data);
    ret->data = ngx_palloc(r->pool, ret->len);
    if (ret->data == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < ret->len; i++) {
        ret->data[i] = start[i];
    }

    return NGX_OK;
}

static ngx_int_t ngx_let_func_rtrim(ngx_http_request_t *r,
        ngx_str_t *str, ngx_str_t *ret)
{
    u_char *end;
    ngx_uint_t i;

    end = str->data + str->len - 1;

    while (end >= str->data && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) {
        end--;
    }

    ret->len = end >= str->data ? (ngx_uint_t)(end - str->data + 1) : 0;
    ret->data = ngx_palloc(r->pool, ret->len);
    if (ret->data == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < ret->len; i++) {
        ret->data[i] = str->data[i];
    }

    return NGX_OK;
}

static ngx_int_t ngx_let_func_replace(ngx_http_request_t *r,
        ngx_str_t *s, ngx_str_t *s1,
        ngx_str_t *s2, ngx_str_t *ret)
{
    u_char *p, *last;
    ngx_uint_t count = 0;
    size_t new_len;
    u_char *new_data, *dst;

    if (s == NULL || s1 == NULL || s2 == NULL || s->len == 0 || s1->len == 0) {
        ret->len = 0;
        ret->data = NULL;
        return NGX_OK;
    }

    last = s->data + s->len - s1->len;
    for (p = s->data; p <= last; p++) {
        if (ngx_strncmp(p, s1->data, s1->len) == 0) {
            count++;
            p += s1->len - 1;
        }
    }

    if (count == 0) {
        ret->len = s->len;
        ret->data = ngx_palloc(r->pool, ret->len);
        if (ret->data == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(ret->data, s->data, s->len);
        return NGX_OK;
    }

    new_len = s->len + count * (s2->len - s1->len);

    new_data = ngx_palloc(r->pool, new_len);
    if (new_data == NULL) {
        return NGX_ERROR;
    }

    dst = new_data;
    p = s->data;
    last = s->data + s->len;

    while (p < last) {
        if (ngx_strncmp(p, s1->data, s1->len) == 0) {
            ngx_memcpy(dst, s2->data, s2->len);
            dst += s2->len;
            p += s1->len;
        } else {
            *dst++ = *p++;
        }
    }

    ret->len = new_len;
    ret->data = new_data;

    return NGX_OK;
}

static ngx_int_t ngx_let_func_reverse(ngx_http_request_t *r,
        ngx_str_t *str, ngx_str_t *ret)
{
    ngx_uint_t i;

    ret->len = str->len;
    ret->data = ngx_palloc(r->pool, ret->len);
    if (ret->data == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < str->len; i++) {
        ret->data[i] = str->data[str->len - 1 - i];
    }

    return NGX_OK;
}

static ngx_int_t ngx_let_func_rand_int(ngx_http_request_t *r,
        ngx_str_t *start_str, ngx_str_t *end_str,
        ngx_str_t *ret)
{
    ngx_int_t start, end, tmp, random;

    start = ngx_atoi(start_str->data, start_str->len);
    if (start == NGX_ERROR) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                      "rand_int: bad \"start\" argument: %V", start_str);
        ret->len = 0;
        return NGX_OK;
    }

    end = ngx_atoi(end_str->data, end_str->len);
    if (end == NGX_ERROR) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                      "rand_int: bad \"end\" argument: %V", end_str);
        ret->len = 0;
        return NGX_OK;
    }

    if (start > end) {
        tmp = start;
        start = end;
        end = tmp;
    }

    random = rand() % (end - start + 1) + start;

    ret->data = ngx_palloc(r->pool, NGX_INT_T_LEN);
    if (ret->data == NULL) {
        return NGX_ERROR;
    }

    ret->len = ngx_sprintf(ret->data, "%i", random) - ret->data;

    return NGX_OK;
}

static ngx_int_t ngx_let_func_repeat(ngx_http_request_t *r,
        ngx_str_t *str, ngx_str_t *n_str,
        ngx_str_t *ret)
{
    ngx_uint_t i, n;
    size_t total_len;

    n = ngx_atoi(n_str->data, n_str->len);
    if (n == (ngx_uint_t) NGX_ERROR || n == 0) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                      "repeat: bad \"n\" argument: %V", n_str);
        ret->len = 0;
        return NGX_OK;
    }

    total_len = str->len * n;

    ret->data = ngx_palloc(r->pool, total_len);
    if (ret->data == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < n; i++) {
        ngx_memcpy(ret->data + i * str->len, str->data, str->len);
    }

    ret->len = total_len;

    return NGX_OK;
}

static ngx_int_t ngx_let_is_valid_number(u_char *data, size_t len)
{
    size_t i;
    int dot_count = 0;

    for (i = 0; i < len; i++) {
        if (data[i] == '.') {
            dot_count++;
            if (dot_count > 1) {
                return NGX_ERROR;
            }
        } else if (data[i] < '0' || data[i] > '9') {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static ngx_int_t ngx_let_func_round(ngx_http_request_t *r,
        ngx_str_t *num_str, ngx_str_t *digits_str,
        ngx_str_t *ret)
{
    ngx_int_t digits, i, j, decimal_point = -1, len;
    u_char *num_data, *result;
    size_t num_len;

    digits = ngx_atoi(digits_str->data, digits_str->len);
    if (digits == NGX_ERROR || digits < 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "round: bad \"digits\" argument: %V", digits_str);
        ret->len = 0;
        return NGX_OK;
    }

    if (ngx_let_is_valid_number(num_str->data, num_str->len) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "round: bad \"num\" argument: %V", num_str);
        ret->len = 0;
        return NGX_OK;
    }

    num_data = num_str->data;
    num_len = num_str->len;

    for (i = 0; i < (ngx_int_t)num_len; i++) {
        if (num_data[i] == '.') {
            decimal_point = i;
            break;
        }
    }

    if (decimal_point == -1) {
        decimal_point = num_len;
        num_len += digits + 1;
        num_data = ngx_palloc(r->pool, num_len + 1);
        if (num_data == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(num_data, num_str->data, num_str->len);
        num_data[decimal_point] = '.';
        for (i = decimal_point + 1; i < (ngx_int_t)num_len; i++) {
            num_data[i] = '0';
        }
        num_data[num_len] = '\0';
        num_len = num_len;
    }

    len = decimal_point + digits + 1;
    if (len > (ngx_int_t)num_len) {
        len = num_len;
    }

    result = ngx_palloc(r->pool, len + 1);
    if (result == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(result, num_data, len);
    result[len] = '\0';

    if (len < (ngx_int_t)num_len && num_data[len] >= '5') {
        for (j = len - 1; j >= 0; j--) {
            if (result[j] == '.') {
                continue;
            }

            if (result[j] < '9') {
                result[j]++;
                break;
            } else {
                result[j] = '0';
                if (j == 0) {
                    u_char *new_result = ngx_palloc(r->pool, len + 2);
                    if (new_result == NULL) {
                        return NGX_ERROR;
                    }
                    new_result[0] = '1';
                    ngx_memcpy(new_result + 1, result, len);
                    new_result[len + 1] = '\0';
                    ret->data = new_result;
                    ret->len = len + 1;
                    return NGX_OK;
                }
            }
        }
    }

    if (len < (decimal_point + digits + 1)) {
        for (i = len; i < (decimal_point + digits + 1); i++) {
            result[i] = '0';
        }
        result[decimal_point + digits + 1] = '\0';
        ret->len = decimal_point + digits + 1;
    } else {
        ret->len = len;
    }

    ret->data = result;

    return NGX_OK;
}

/* Call function by name & return result */
static ngx_int_t ngx_let_call_fun(ngx_http_request_t *r,
        ngx_str_t *name, ngx_array_t *args, ngx_str_t *value)
{
    ngx_str_t *sargs = args->elts;

    /* TODO: implement hashtable for faster lookup */

#define IF_FUNC(nm, nargs) \
    if (sizeof(#nm) - 1 == name->len \
            && !ngx_strncmp(#nm, name->data, name->len)) { \
        if (nargs != args->nelts) { \
            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, \
                "let function '%*s' expects %d arguments, %d provided", \
                    name->len, name->data, nargs, args->nelts); \
            return NGX_ERROR; \
        }

#define CALL_FUNC_0(nm) \
    IF_FUNC(nm, 0) \
        return ngx_let_func_##nm(r, value); \
    }

#define CALL_FUNC_1(nm) \
    IF_FUNC(nm, 1) \
        return ngx_let_func_##nm(r, sargs, value); \
    }

#define CALL_FUNC_2(nm) \
    IF_FUNC(nm, 2) \
        return ngx_let_func_##nm(r, sargs, sargs + 1, value); \
    }

#define CALL_FUNC_3(nm) \
    IF_FUNC(nm, 3) \
        return ngx_let_func_##nm(r, sargs, sargs + 1, sargs + 2, value); \
    }
    
    CALL_FUNC_0(rand);

    /* cryptographic hashes */
    CALL_FUNC_1(md4);
    CALL_FUNC_1(md5);

    CALL_FUNC_1(sha1);
    CALL_FUNC_1(sha224);
    CALL_FUNC_1(sha256);
    CALL_FUNC_1(sha384);
    CALL_FUNC_1(sha512);

    CALL_FUNC_1(ripemd160);

    /* string operations */
    CALL_FUNC_1(len);
    CALL_FUNC_1(lower);
    CALL_FUNC_1(upper);
    CALL_FUNC_1(trim);
    CALL_FUNC_1(ltrim);
    CALL_FUNC_1(rtrim);
    CALL_FUNC_1(reverse);
    CALL_FUNC_2(position);
    CALL_FUNC_2(repeat);
    CALL_FUNC_3(substr);
    CALL_FUNC_3(replace);

    /* integer operations */
    CALL_FUNC_2(rand_int);
    CALL_FUNC_2(max);
    CALL_FUNC_2(min);
    CALL_FUNC_2(round);

    ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                "let undefined function '%*s'", name->len, name->data);

    return NGX_ERROR;
}

/* Processes positive integers only */
static ngx_int_t ngx_let_apply_binary_integer_op(ngx_http_request_t *r, int op, 
        ngx_array_t* args, ngx_str_t* value)
{
    ngx_str_t* str;
    int left, right;
    unsigned sz;

    if (args->nelts != 2) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, 
                "let not enough argument for binary operation");
        return NGX_ERROR;
    }
    
    str = args->elts;

    left = ngx_let_toi(str);
    if (left != NGX_ERROR) {
        ++str;
        right = ngx_let_toi(str);
    }
    
    if (left == NGX_ERROR || right == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, 
                "let error parsing argument '%*s'", str->len, str->data);
        return NGX_ERROR;
    }
    
    switch(op) {
        
        case '+':
            left += right;
            break;
            
        case '-':
            left -= right;
            break;

        case '*':
            left *= right;
            break;

        case '/':
            left /= right;
            break;

        case '%':
            left %= right;
            break;

        case '&':
            left &= right;
            break;

        case '|':
            left |= right;
            break;

        default:
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, 
                    "let unexpected operation '%c'", op);
            return NGX_ERROR;
    }
    
    value->len = 64; /*TODO: better size? */
    value->data = ngx_palloc(r->pool, value->len);
    
    sz = snprintf((char*)value->data, value->len, "%d", left);

    if (sz < value->len)
        value->len = sz;
    
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "let applying binary operation '%c' %d: %d", op, right, left);

    return NGX_OK;
}

static ngx_int_t ngx_let_get_node_value(ngx_http_request_t* r, ngx_let_node_t* node,
        ngx_str_t* value)
{
    ngx_http_variable_value_t* vv;
    ngx_array_t args;
    ngx_let_node_t** anode;
    ngx_str_t* astr;
    ngx_uint_t n;
    ngx_int_t ret;
    u_char* s;
    int *cap;
    ngx_int_t ncap;

    if (node == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, 
                "let NULL node");
        return NGX_ERROR;
    }

    switch(node->type) {
        
        case NGX_LTYPE_VARIABLE:
            
            vv = ngx_http_get_indexed_variable(r, node->index);
                
            if (vv == NULL || vv->not_found) {
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, 
                        "let variable %d not found", node->index);
                    
                return NGX_ERROR;
            }

            value->data = vv->data;
            value->len = vv->len;
            
            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                        "let getting variable %d: '%*s'", node->index, value->len, value->data);

            break;

        case NGX_LTYPE_CAPTURE:

            if (node->index >= (ngx_int_t)r->ncaptures)
                return NGX_ERROR;

            cap = r->captures;

            ncap = node->index * 2;

            value->data = r->captures_data + cap[ncap];
            value->len = cap[ncap + 1] - cap[ncap];

            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                        "let getting capture %d: '%*s'", node->index, value->len, value->data);

            break;
            
        case NGX_LTYPE_LITERAL:
            
            *value = node->name;
            
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                        "let getting literal: '%*s'", value->len, value->data);
            
            break;

        case NGX_LTYPE_FUNCTION:

            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                        "let calling function '%*s'; argc: %d", 
                        node->name.len, node->name.data, node->args.nelts);
            
            /* parse arguments */
            ngx_array_init(&args, r->pool, node->args.nelts, sizeof(ngx_str_t));

            astr = ngx_array_push_n(&args, node->args.nelts);
            anode = node->args.elts;
        
            for(n = 0; n < node->args.nelts; ++n) {
                
                ret = ngx_let_get_node_value(r, *anode++, astr++);
                if (ret != NGX_OK)
                    return ret;
            }

            ret = ngx_let_call_fun(r, &node->name, &args, value);

            if (ret != NGX_OK)
                return ret;

            break;
            
        case NGX_LTYPE_OPERATION:
            
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                        "let applying operation '%c'; argc: %d", node->index, node->args.nelts);
            
            /* parse arguments */
            ngx_array_init(&args, r->pool, node->args.nelts, sizeof(ngx_str_t));

            astr = ngx_array_push_n(&args, node->args.nelts);
            anode = node->args.elts;
        
            for(n = 0; n < node->args.nelts; ++n) {
                
                ret = ngx_let_get_node_value(r, *anode++, astr++);
                if (ret != NGX_OK)
                    return ret;
            }
            
            if (strchr("+-*/%&|", node->index)) {
                
                /* binary integer operation */

                ret = ngx_let_apply_binary_integer_op(r, node->index, &args, value);
                if (ret != NGX_OK)
                    return ret;
                
            } else if (node->index == '.') {
                
                /* string concatenation */

                value->len = 0;
                astr = args.elts;
                
                for(n = 0; n < args.nelts; ++n, ++astr)
                    value->len += astr->len;

                value->data = ngx_palloc(r->pool, value->len);

                astr = args.elts;
                s = value->data;
                for(n = 0, s = value->data; n < args.nelts; ++n, s += astr++->len)
                    memcpy(s, astr->data, astr->len);
                
                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                        "let %d strings concatenated '%*s'", args.nelts, value->len, value->data);
            }

            break;
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_let_variable(ngx_http_request_t *r,
            ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_let_node_t* node = (ngx_let_node_t*)data;
    ngx_str_t value;
    ngx_int_t ret;

    ret = ngx_let_get_node_value(r, node, &value);

    if (ret == NGX_OK) {

        v->len = value.len;
        v->data = value.data;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
            
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "let variable accessed");
    }

    return ret;
}

static char* ngx_http_let_let(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value;
    ngx_http_variable_t *v;

    srand(time(0));
    
    value = cf->args->elts;
    
    ngx_log_debug0(NGX_LOG_INFO, cf->log, 0, "let command handler");

    if (value[1].data[0] != '$') {
        return "needs variable as the first argument";
    }

	if (value[1].len <= 1) {
		return "needs variable name";
    }

    value[1].data++;
    value[1].len--;

    v = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE);

    v->get_handler = ngx_http_let_variable;
    v->data = (uintptr_t)ngx_parse_let_expr(cf);
    
    return NGX_CONF_OK;
}
