/* SRCTools Discord run webhook worker - minimal C implementation. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <strings.h>
#include <mbedtls/net.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr.h>

/* ---------------- allocation / buffer ---------------- */

static void *xmalloc(size_t n) { void *p = malloc(n ? n : 1); if (!p) exit(1); return p; }
static void *xrealloc(void *p, size_t n) { void *q = realloc(p, n ? n : 1); if (!q) exit(1); return q; }
static char *xstrdup(const char *s) { size_t n = strlen(s) + 1; char *p = xmalloc(n); memcpy(p, s, n); return p; }

typedef struct { char *data; size_t len; size_t cap; } Buf;
static void buf_init(Buf *b) { b->cap = 256; b->len = 0; b->data = xmalloc(b->cap); b->data[0] = 0; }
static void buf_reserve(Buf *b, size_t extra) { if (b->len + extra + 1 > b->cap) { while (b->len + extra + 1 > b->cap) b->cap *= 2; b->data = xrealloc(b->data, b->cap); } }
static void buf_add(Buf *b, const char *s, size_t n) { buf_reserve(b, n); memcpy(b->data + b->len, s, n); b->len += n; b->data[b->len] = 0; }
static void buf_puts(Buf *b, const char *s) { buf_add(b, s, strlen(s)); }
static void buf_printf(Buf *b, const char *fmt, ...) { char tmp[1024]; va_list ap; va_start(ap, fmt); vsnprintf(tmp, sizeof tmp, fmt, ap); va_end(ap); buf_puts(b, tmp); }
static void buf_free(Buf *b) { free(b->data); b->data = NULL; b->len = b->cap = 0; }

static char *trim_dup(const char *s) {
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r' || s[n - 1] == '\n')) n--;
    char *out = xmalloc(n + 1); memcpy(out, s, n); out[n] = 0; return out;
}

static void sleep_ms(long ms) { struct timespec ts; ts.tv_sec = ms / 1000; ts.tv_nsec = (ms % 1000) * 1000000L; nanosleep(&ts, NULL); }

/* ---------------- tiny JSON parser ---------------- */

typedef enum { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ } JType;
typedef struct Json Json;
struct Json {
    JType t;
    bool b;
    double num;
    char *str;
    char **keys;
    Json **vals;
    size_t nkeys, keys_cap;
    Json **items;
    size_t nitems, items_cap;
};

typedef struct { const char *p, *end; } JP;

static Json *jnew(JType t) { Json *j = xmalloc(sizeof *j); memset(j, 0, sizeof *j); j->t = t; return j; }
static void jskip(JP *ps) { while (ps->p < ps->end && (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\n' || *ps->p == '\r')) ps->p++; }
static int jhex(char c) { if (c >= '0' && c <= '9') return c - '0'; if (c >= 'a' && c <= 'f') return c - 'a' + 10; if (c >= 'A' && c <= 'F') return c - 'A' + 10; return -1; }
static char *jstring(JP *ps, size_t *outlen) {
    if (ps->p >= ps->end || *ps->p != '"') return NULL;
    ps->p++;
    Buf b; buf_init(&b);
    while (ps->p < ps->end && *ps->p != '"') {
        char c = *ps->p++;
        if (c == '\\') { if (ps->p >= ps->end) break; char e = *ps->p++; if (e == 'n') buf_add(&b, "\n", 1); else if (e == 't') buf_add(&b, "\t", 1); else if (e == 'r') buf_add(&b, "\r", 1); else if (e == 'b') buf_add(&b, "\b", 1); else if (e == 'f') buf_add(&b, "\f", 1); else if (e == 'u') { ps->p += 4; } else buf_add(&b, &e, 1); }
        else buf_add(&b, &c, 1);
    }
    if (ps->p < ps->end && *ps->p == '"') ps->p++;
    *outlen = b.len;
    char *s = xmalloc(b.len + 1); memcpy(s, b.data, b.len); s[b.len] = 0; free(b.data);
    return s;
}
static Json *jvalue(JP *ps) {
    jskip(ps);
    if (ps->p >= ps->end) return NULL;
    char c = *ps->p;
    if (c == '{') {
        Json *o = jnew(J_OBJ); ps->p++; jskip(ps);
        if (ps->p < ps->end && *ps->p == '}') { ps->p++; return o; }
        while (ps->p < ps->end) {
            jskip(ps); char *key = jstring(ps, NULL); if (!key) break; jskip(ps); if (ps->p < ps->end && *ps->p == ':') ps->p++;
            Json *v = jvalue(ps);
            if (o->nkeys == o->keys_cap) { o->keys_cap = o->keys_cap ? o->keys_cap * 2 : 4; o->keys = xrealloc(o->keys, o->keys_cap * sizeof(char *)); o->vals = xrealloc(o->vals, o->keys_cap * sizeof(Json *)); }
            o->keys[o->nkeys] = key; o->vals[o->nkeys] = v; o->nkeys++;
            jskip(ps);
            if (ps->p < ps->end && *ps->p == ',') { ps->p++; continue; }
            if (ps->p < ps->end && *ps->p == '}') { ps->p++; break; }
        }
        return o;
    }
    if (c == '[') {
        Json *a = jnew(J_ARR); ps->p++; jskip(ps);
        if (ps->p < ps->end && *ps->p == ']') { ps->p++; return a; }
        while (ps->p < ps->end) {
            Json *v = jvalue(ps);
            if (a->nitems == a->items_cap) { a->items_cap = a->items_cap ? a->items_cap * 2 : 4; a->items = xrealloc(a->items, a->items_cap * sizeof(Json *)); }
            a->items[a->nitems++] = v;
            jskip(ps);
            if (ps->p < ps->end && *ps->p == ',') { ps->p++; continue; }
            if (ps->p < ps->end && *ps->p == ']') { ps->p++; break; }
        }
        return a;
    }
    if (c == '"') { Json *s = jnew(J_STR); s->str = jstring(ps, NULL); return s; }
    if (c == 't') { if (ps->end - ps->p >= 4 && strncmp(ps->p, "true", 4) == 0) { ps->p += 4; Json *j = jnew(J_BOOL); j->b = true; return j; } return NULL; }
    if (c == 'f') { if (ps->end - ps->p >= 5 && strncmp(ps->p, "false", 5) == 0) { ps->p += 5; Json *j = jnew(J_BOOL); j->b = false; return j; } return NULL; }
    if (c == 'n') { if (ps->end - ps->p >= 4 && strncmp(ps->p, "null", 4) == 0) { ps->p += 4; return jnew(J_NULL); } return NULL; }
    { Json *j = jnew(J_NUM); char *endp; double d = strtod(ps->p, &endp); j->num = d; ps->p = endp; return j; }
}
static Json *jparse(JP *ps) { return jvalue(ps); }
static void jfree(Json *j) {
    if (!j) return;
    if (j->t == J_OBJ) { for (size_t i = 0; i < j->nkeys; i++) { free(j->keys[i]); jfree(j->vals[i]); } free(j->keys); free(j->vals); }
    if (j->t == J_ARR) { for (size_t i = 0; i < j->nitems; i++) jfree(j->items[i]); free(j->items); }
    free(j->str); free(j);
}
static const Json *jget(const Json *o, const char *key) { if (!o || o->t != J_OBJ) return NULL; for (size_t i = 0; i < o->nkeys; i++) if (strcasecmp(o->keys[i], key) == 0) return o->vals[i]; return NULL; }
static double jnum(const Json *o, const char *key, double dflt) { const Json *v = jget(o, key); return (v && v->t == J_NUM) ? v->num : dflt; }
static const char *jstr(const Json *o, const char *key, const char *dflt) { const Json *v = jget(o, key); if (v && v->t == J_STR) return v->str ? v->str : ""; return dflt; }
static const Json *jarr_get(const Json *o, const char *key) { const Json *v = jget(o, key); if (v && v->t == J_ARR) return v; return NULL; }

/* ---------------- http via mbedtls ---------------- */

static mbedtls_net_context net_ctx;
static mbedtls_ssl_context ssl_ctx;
static mbedtls_ssl_config ssl_conf;

static int http_request(const char *host, int port, const char *path, const char *method, const char *body, char **out_body, size_t *out_len, long *out_status) {
    int rc = -1;
    mbedtls_net_config netcfg; mbedtls_net_config_init(&netcfg); netcfg.timeout = 10000;
    mbedtls_net_init(&net_ctx, &netcfg);
    mbedtls_ssl_conf_init(&ssl_conf);
    mbedtls_ssl_conf_authmode(&ssl_conf, mbedtls_auth_ca_required);
    mbedtls_ssl_conf_set(&ssl_conf, NULL);
    mbedtls_ssl_init(&ssl_ctx);
    mbedtls_ssl_setup(&ssl_ctx, &ssl_conf);
    mbedtls_ssl_start(&ssl_ctx);
    if (mbedtls_net_connect(&net_ctx, host, port, &ssl_ctx) != 0) return -1;
    if (mbedtls_ssl_handshake(&ssl_ctx) != 0) return -1;
    Buf req; buf_init(&req);
    buf_puts(&req, method); buf_puts(&req, " "); buf_puts(&req, path); buf_puts(&req, " HTTP/1.1\r\nHost: "); buf_puts(&req, host); buf_puts(&req, "\r\nContent-Type: application/json\r\nContent-Length: "); buf_printf(&req, "%zu\r\nConnection: close\r\n\r\n", body ? strlen(body) : 0);
    if (mbedtls_ssl_write(&ssl_ctx, req.data, req.len) != 0) goto done;
    unsigned char rbuf[8192];
    Buf resp; buf_init(&resp);
    size_t rlen = 0;
    int closed = 0;
    while (!closed) {
        int rrc = mbedtls_ssl_read(&ssl_ctx, rbuf, sizeof rbuf, &rlen);
        if (rrc != 0) { closed = 1; break; }
        if (rlen == 0) break;
        buf_add(&resp, (char *)rbuf, rlen);
        rlen = 0;
    }
    const char *hdr_end = strstr(resp.data, "\r\n\r\n");
    if (hdr_end) {
        *out_status = (long)strtol(hdr_end + 4, NULL, 10);
        *out_body = xstrdup(hdr_end + 4);
        *out_len = strlen(hdr_end + 4);
        rc = 0;
    }
done:
    mbedtls_ssl_free(&ssl_ctx);
    mbedtls_net_free(&net_ctx);
    mbedtls_ssl_conf_free(&ssl_conf);
    return rc;
}

/* ---------------- discord ---------------- */

static void json_escape(Buf *b, const char *s) {
    buf_add(b, "\"", 1);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p == '"' || *p == '\\') { char tmp[2] = { '\\', (char)*p }; buf_add(b, tmp, 2); }
        else if (*p == '\n') buf_add(b, "\\n", 2);
        else if (*p == '\r') buf_add(b, "\\r", 2);
        else if (*p == '\t') buf_add(b, "\\t", 2);
        else buf_add(b, (const char *)p, 1);
    }
    buf_add(b, "\"", 1);
}

static void build_discord_payload(Buf *b, const char *title, const char *url, const char *desc, long color) {
    buf_puts(b, "{\"embeds\":[{\"title\":"); json_escape(b, title);
    buf_puts(b, ",\"url\":"); json_escape(b, url);
    buf_puts(b, ",\"description\":"); json_escape(b, desc);
    buf_printf(b, ",\"color\":%ld}", color);
    buf_puts(b, "],\"allowed_mentions\":{\"parse\":[]}}");
}

int main(void) { return 0; }

#endif
