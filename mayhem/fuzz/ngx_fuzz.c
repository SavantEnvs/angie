/*
 * In-process libFuzzer harness for Angie, modelled on OSS-Fuzz nginx's
 * http_request_fuzzer: initialise a cycle once from a fixed configuration,
 * then feed every input through a fake connection into the listener's public
 * handler (ngx_http_init_connection / ngx_mail_init_connection /
 * ngx_stream_init_connection).  The protocol and configuration are selected
 * at compile time with -DFUZZ_MODE=<n> (see the FUZZ_* constants below).
 *
 * Environment mocking only: listen/bind/connect/setsockopt/shutdown/chown/
 * chmod/getpwnam/getgrnam are wrapped with -Wl,--wrap so no real socket is
 * bound or connected; Angie's own code is linked unchanged.
 *
 * Per-input state: the client/upstream connections and their events are
 * allocated per input; the timer tree and posted queues are reset per input,
 * and every timer still armed when the input is exhausted is fired (its
 * timeout handler closes the connection).  A connection still open after
 * that is force-closed (fd, timers and posted events released, pool
 * destroyed), so nothing outlives the input.  Every shared memory zone
 * (metric zones) is re-initialised before each input, as at startup, so keys
 * recorded by one input never change the path a later one takes.  Only the
 * read-only cycle (parsed configuration) is kept across inputs.
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>
#include <ngx_mail.h>
#include <ngx_stream.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>

#define FUZZ_HTTP           1   /* HTTP/1.x client request (+ upstream reply after separator) */
#define FUZZ_HTTP2          2   /* HTTP/2 cleartext connection */
#define FUZZ_PROXY_PROTOCOL 3   /* PROXY v1/v2 header + HTTP request */
#define FUZZ_PROXY_REPLY    4   /* HTTP/1 upstream reply via proxy_pass */
#define FUZZ_GRPC_REPLY     5   /* gRPC upstream reply */
#define FUZZ_PROXY_V2_REPLY 6   /* HTTP/2 upstream reply (proxy_http_version 2) */
#define FUZZ_FASTCGI_REPLY  7   /* FastCGI upstream reply */
#define FUZZ_IMAP           8
#define FUZZ_POP3           9
#define FUZZ_SMTP          10
#define FUZZ_MQTT          11   /* stream mqtt_preread */
#define FUZZ_RDP           12   /* stream rdp_preread */
#define FUZZ_SSL_PREREAD   13   /* stream ssl_preread */
#define FUZZ_UWSGI_REPLY   14   /* uwsgi upstream reply */
#define FUZZ_SCGI_REPLY    15   /* SCGI upstream reply */
#define FUZZ_MEMCACHED_REPLY 16 /* memcached upstream reply */
#define FUZZ_MP4_FILE      17   /* served file parsed by the mp4 module */
#define FUZZ_SSI_FILE      18   /* served file parsed by the SSI filter */
#define FUZZ_IMAP_PROXY    19   /* IMAP backend server replies (mail proxy) */
#define FUZZ_POP3_PROXY    20   /* POP3 backend server replies (mail proxy) */
#define FUZZ_SMTP_PROXY    21   /* SMTP backend server replies (mail proxy) */

#define IS_REPLY_MODE(m) (((m) >= FUZZ_PROXY_REPLY && (m) <= FUZZ_FASTCGI_REPLY) \
                          || ((m) >= FUZZ_UWSGI_REPLY && (m) <= FUZZ_MEMCACHED_REPLY))
#define IS_FILE_MODE(m)  ((m) == FUZZ_MP4_FILE || (m) == FUZZ_SSI_FILE)
#define IS_MAIL_PROXY_MODE(m) ((m) >= FUZZ_IMAP_PROXY && (m) <= FUZZ_SMTP_PROXY)
#define IS_MAIL_MODE(m)  (((m) >= FUZZ_IMAP && (m) <= FUZZ_SMTP) || IS_MAIL_PROXY_MODE(m))
#define IS_IMAP(m) ((m) == FUZZ_IMAP || (m) == FUZZ_IMAP_PROXY)
#define IS_POP3(m) ((m) == FUZZ_POP3 || (m) == FUZZ_POP3_PROXY)

#ifndef FUZZ_MODE
#error "define FUZZ_MODE"
#endif

#define HTTP_COMMON \
"    server_tokens off;\n" \
"    default_type application/octet-stream;\n" \
"    error_log stderr emerg;\n" \
"    client_body_temp_path tmp/body;\n" \
"    proxy_temp_path tmp/proxy;\n" \
"    fastcgi_temp_path tmp/fcgi;\n" \
"    uwsgi_temp_path tmp/uwsgi;\n" \
"    scgi_temp_path tmp/scgi;\n" \
"    proxy_ignore_client_abort on;\n" \
"    log_format main '$remote_addr $request_length $bytes_sent \"$request\" $status $uri $args $http_user_agent $proxy_protocol_addr $request_time';\n" \
"    access_log /dev/null main;\n" \
"    metric_zone mz:256k count;\n" \
"    metric_complex_zone mcz:256k discard_key=other {\n" \
"        hist histogram 1 10 100;\n" \
"        avg  average exp;\n" \
"    }\n" \
"    map $uri $mapped { default 0; ~^/a(?<cap>.*)$ $cap; }\n" \
"    upstream backend { server 127.0.0.1:1010 max_fails=0; }\n"

#define HTTP_LOCATIONS \
"        root html;\n" \
"        location / {\n" \
"            metric mz $uri on=request;\n" \
"            metric mcz $arg_k=$request_length on=end;\n" \
"            index index.html;\n" \
"        }\n" \
"        location /rw/ {\n" \
"            rewrite ^/rw/(.*)/(.*)$ /static/$2?x=$1&y=$arg_y last;\n" \
"            rewrite ^/rw/(.*)$ /esc/$1 break;\n" \
"            return 200 \"$1 $args $mapped\";\n" \
"        }\n" \
"        location /esc/ { rewrite ^/esc/(.*)$ /static/$1?q=$1 redirect; }\n" \
"        location /set/ { set $v \"$uri:$args:$http_host\"; return 200 $v; }\n" \
"        location /ret { return 302 /x$request_uri; }\n" \
"        location /static/ { autoindex on; }\n" \
"        location /api/ { api /; }\n" \
"        location /proxy/ {\n" \
"            proxy_pass http://backend;\n" \
"            proxy_set_header X-Uri $uri;\n" \
"            proxy_buffering off;\n" \
"        }\n" \
"        location /gzip/ { gzip on; gzip_min_length 1; return 200 aaaaaaaaaaaaaaaaaaaaaaaa; }\n"

static const char configuration[] =
"error_log stderr emerg;\n"
"pid tmp/angie.pid;\n"
"events {\n"
"    worker_connections 64;\n"
"    accept_mutex off;\n"
"}\n"
#if FUZZ_MODE == FUZZ_HTTP || FUZZ_MODE == FUZZ_HTTP2 || FUZZ_MODE == FUZZ_PROXY_PROTOCOL
"http {\n"
HTTP_COMMON
#if FUZZ_MODE == FUZZ_PROXY_PROTOCOL
"    set_real_ip_from 0.0.0.0/0;\n"
"    real_ip_header proxy_protocol;\n"
#endif
"    server {\n"
#if FUZZ_MODE == FUZZ_PROXY_PROTOCOL
"        listen 127.0.0.1:8080 proxy_protocol;\n"
"        add_header X-PP \"$proxy_protocol_addr:$proxy_protocol_port $proxy_protocol_server_addr $proxy_protocol_tlv_alpn $proxy_protocol_tlv_0x01 $proxy_protocol_tlv_unique_id\";\n"
#else
"        listen 127.0.0.1:8080;\n"
#endif
#if FUZZ_MODE == FUZZ_HTTP2
"        http2 on;\n"
#endif
"        server_name localhost ~^(?<sub>.+)\\.example\\.com$;\n"
HTTP_LOCATIONS
"    }\n"
"}\n"
#elif IS_REPLY_MODE(FUZZ_MODE) || IS_FILE_MODE(FUZZ_MODE)
"http {\n"
HTTP_COMMON
"    server {\n"
"        listen 127.0.0.1:8080;\n"
"        location / {\n"
#if FUZZ_MODE == FUZZ_PROXY_REPLY
"            proxy_pass http://backend;\n"
"            proxy_buffering on;\n"
"            proxy_redirect http://backend/ /;\n"
"            proxy_cookie_domain backend localhost;\n"
"            proxy_cookie_path /one/ /;\n"
"            proxy_pass_header X-Accel-Redirect;\n"
"            sub_filter 'a' 'b';\n"
"            sub_filter_once off;\n"
"            ssi on;\n"
"            gunzip on;\n"
#elif FUZZ_MODE == FUZZ_GRPC_REPLY
"            grpc_pass grpc://backend;\n"
#elif FUZZ_MODE == FUZZ_PROXY_V2_REPLY
"            proxy_pass http://backend;\n"
"            proxy_http_version 2;\n"
#elif FUZZ_MODE == FUZZ_FASTCGI_REPLY
"            fastcgi_pass backend;\n"
"            fastcgi_param SCRIPT_FILENAME /x$fastcgi_script_name;\n"
"            fastcgi_buffering on;\n"
#elif FUZZ_MODE == FUZZ_UWSGI_REPLY
"            uwsgi_pass backend;\n"
"            uwsgi_buffering on;\n"
#elif FUZZ_MODE == FUZZ_SCGI_REPLY
"            scgi_pass backend;\n"
"            scgi_buffering off;\n"
#elif FUZZ_MODE == FUZZ_MEMCACHED_REPLY
"            set $memcached_key \"$uri?$args\";\n"
"            memcached_pass backend;\n"
"            memcached_gzip_flag 2;\n"
#elif FUZZ_MODE == FUZZ_MP4_FILE
"            root html;\n"
"            mp4;\n"
"            mp4_buffer_size 16k;\n"
"            mp4_max_buffer_size 1m;\n"
"            mp4_start_key_frame on;\n"
#elif FUZZ_MODE == FUZZ_SSI_FILE
"            root html;\n"
"            ssi on;\n"
"            ssi_types *;\n"
"            ssi_value_length 64;\n"
"            set $sv \"$uri:$args\";\n"
"        }\n"
"        location /inc/ {\n"
"            root html;\n"
"            ssi on;\n"
#endif
"        }\n"
"    }\n"
"}\n"
#elif IS_MAIL_MODE(FUZZ_MODE)
"mail {\n"
"    auth_http 127.0.0.1:1010/auth;\n"
"    server {\n"
"        listen 127.0.0.1:8080;\n"
#if IS_IMAP(FUZZ_MODE)
"        protocol imap;\n"
"        imap_auth plain login cram-md5 external;\n"
"        imap_capabilities IMAP4rev1 IDLE LITERAL+;\n"
#elif IS_POP3(FUZZ_MODE)
"        protocol pop3;\n"
"        pop3_auth plain apop cram-md5 external;\n"
#else
"        protocol smtp;\n"
"        smtp_auth plain login cram-md5 external none;\n"
"        resolver off;\n"
"        xclient off;\n"
#if FUZZ_MODE == FUZZ_SMTP_PROXY
"        proxy_smtp_auth on;\n"
#endif
#endif
#if IS_MAIL_PROXY_MODE(FUZZ_MODE)
"        proxy_pass_error_message on;\n"
#endif
"    }\n"
"}\n"
#else
"stream {\n"
"    error_log stderr emerg;\n"
"    log_format sl '$remote_addr $protocol $status $bytes_received $session_time $mapped';\n"
"    access_log /dev/null sl;\n"
"    upstream backend { server 127.0.0.1:1010; }\n"
"    metric_zone smz:256k count;\n"
#if FUZZ_MODE == FUZZ_MQTT
"    map $mqtt_preread_clientid$mqtt_preread_username $mapped { default 0; ~^a(?<c>.*) $c; }\n"
#elif FUZZ_MODE == FUZZ_RDP
"    map $rdp_cookie$rdp_cookie_mstshash $mapped { default 0; ~^a(?<c>.*) $c; }\n"
#else
"    map $ssl_preread_server_name:$ssl_preread_alpn_protocols:$ssl_preread_protocol $mapped { default 0; ~^a(?<c>.*) $c; }\n"
#endif
"    server {\n"
"        listen 127.0.0.1:8080;\n"
#if FUZZ_MODE == FUZZ_MQTT
"        mqtt_preread on;\n"
#elif FUZZ_MODE == FUZZ_RDP
"        rdp_preread on;\n"
#else
"        ssl_preread on;\n"
#endif
"        metric smz $mapped on=end;\n"
"        proxy_pass backend;\n"
"    }\n"
"}\n"
#endif
;

/* A fixed client request for the upstream-reply modes: the fuzz input is the reply. */
static const char fixed_request[] =
"GET /up/x.php?a=1 HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip\r\n"
"Cookie: c=1\r\n\r\n";

#if FUZZ_MODE == FUZZ_MP4_FILE
static const char file_request[] = "GET /f.mp4?start=0.5&end=4.5 HTTP/1.0\r\nHost: localhost\r\n\r\n";
static const char file_name[] = "html/f.mp4";
#elif FUZZ_MODE == FUZZ_SSI_FILE
static const char file_request[] = "GET /f.shtml?a=1 HTTP/1.0\r\nHost: localhost\r\n\r\n";
static const char file_name[] = "html/f.shtml";
#endif

#if IS_MAIL_PROXY_MODE(FUZZ_MODE)
/*
 * Mail proxy modes: a fixed client login, a fixed successful auth_http reply
 * (first upstream connection, port 1010) sending the session to the backend
 * on port 1011, whose byte stream is the fuzz input.
 */
#if FUZZ_MODE == FUZZ_IMAP_PROXY
static const char mail_login[] = "a1 LOGIN user pass\r\n";
#elif FUZZ_MODE == FUZZ_POP3_PROXY
static const char mail_login[] = "USER user\r\nPASS pass\r\n";
#else
static const char mail_login[] = "EHLO client\r\nAUTH PLAIN AHVzZXIAcGFzcw==\r\n";
#endif
static const char auth_reply[] =
"HTTP/1.0 200 OK\r\nAuth-Status: OK\r\nAuth-Server: 127.0.0.1\r\n"
"Auth-Port: 1011\r\n\r\n";
#define AUTH_PORT 1010
#endif

/* Separator between the client request and the upstream reply (FUZZ_HTTP). */
static const char reply_sep[] = "\r\n--REPLY--\r\n";

struct fuzz_buf { const u_char *data; size_t len; };

static struct fuzz_buf  client_in;
static struct fuzz_buf  upstream_in;
#if IS_MAIL_PROXY_MODE(FUZZ_MODE)
static struct fuzz_buf  auth_in;
static int              auth_fd = -1;  /* socket connected to the auth_http port */
#endif
static int              client_eof;
static ngx_cycle_t     *cycle;
static ngx_log_t        fuzz_log;
static ngx_open_file_t  fuzz_log_file;

static ssize_t
buf_read(struct fuzz_buf *b, u_char *buf, size_t size)
{
    if (size > b->len) {
        size = b->len;
    }
    if (size) {
        memcpy(buf, b->data, size);
    }
    b->data += size;
    b->len -= size;
    return size;
}

/* the event state a real non-blocking recv() leaves behind (ngx_unix_recv) */
static void
recv_state(ngx_connection_t *c, ssize_t n, size_t size)
{
    if (n == 0) {
        c->read->eof = 1;
        c->read->ready = 0;
    } else if ((size_t) n < size) {
        c->read->ready = 0;
    }
}

static ssize_t
client_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    ssize_t n;

    if (client_in.len == 0 && !client_eof) {
        /* the client sent everything but keeps the connection open */
        c->read->ready = 0;
        return NGX_AGAIN;
    }
    n = buf_read(&client_in, buf, size);
    recv_state(c, n, size);
    return n;
}

static struct fuzz_buf *
upstream_buf(ngx_connection_t *c)
{
#if IS_MAIL_PROXY_MODE(FUZZ_MODE)
    if (auth_fd != -1 && c->fd == auth_fd) {
        return &auth_in;
    }
#endif
    return &upstream_in;
}

static ssize_t
upstream_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    ssize_t n;
#if IS_MAIL_PROXY_MODE(FUZZ_MODE)
    /*
     * A mail backend answers in lock-step: one reply line per command, so
     * deliver at most one line per read.  ngx_mail_proxy_read_response()
     * discards whatever follows the line it parsed during the login phase.
     */
    if (upstream_buf(c) == &upstream_in) {
        const u_char *lf = memchr(upstream_in.data, '\n', upstream_in.len);
        if (lf && (size_t) (lf - upstream_in.data) + 1 < size) {
            size = lf - upstream_in.data + 1;
        }
    }
#endif
    n = buf_read(upstream_buf(c), buf, size);
    recv_state(c, n, size);
    return n;
}

static ssize_t
upstream_recv_chain(ngx_connection_t *c, ngx_chain_t *cl, off_t limit)
{
    ssize_t  n, total = 0;
    size_t   want = 0;

    for (; cl; cl = cl->next) {
        size_t room = cl->buf->end - cl->buf->last;
        if (limit && (off_t) (total + room) > limit) {
            room = limit - total;
        }
        want += room;
        n = buf_read(upstream_buf(c), cl->buf->last, room);
        total += n;
        if ((size_t) n < room || (limit && total >= limit)) {
            break;
        }
    }
    recv_state(c, total, want);
    return total;
}

static ssize_t
fake_send(ngx_connection_t *c, u_char *buf, size_t size)
{
    return size;
}

/* Everything is "sent": consume every buffer of the chain. */
static ngx_chain_t *
fake_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    for (; in; in = in->next) {
        if (ngx_buf_special(in->buf)) {
            continue;
        }
        if (in->buf->in_file) {
            in->buf->file_pos = in->buf->file_last;
        }
        if (ngx_buf_in_memory(in->buf)) {
            c->sent += in->buf->last - in->buf->pos;
            in->buf->pos = in->buf->last;
        }
    }
    c->read->ready = 1;
    c->write->ready = 1;
    return NULL;
}

static ngx_int_t ev_add(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags) { return NGX_OK; }
static ngx_int_t ev_del(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags) { return NGX_OK; }
static ngx_int_t ev_init(ngx_cycle_t *cycle, ngx_msec_t timer) { return NGX_OK; }

/* environment mocks (libc), applied with -Wl,--wrap=<name> */
int __wrap_listen(int fd, int backlog) { return 0; }
int __wrap_bind(int fd, const struct sockaddr *a, socklen_t l) { return 0; }
int __wrap_connect(int fd, const struct sockaddr *a, socklen_t l)
{
#if IS_MAIL_PROXY_MODE(FUZZ_MODE)
    /* remember which socket goes to the auth_http server (see upstream_buf) */
    if (a && ngx_inet_get_port((struct sockaddr *) a) == AUTH_PORT) {
        auth_fd = fd;
    } else if (fd == auth_fd) {
        auth_fd = -1;
    }
#endif
    return 0;
}
int __wrap_setsockopt(int fd, int lv, int n, const void *v, socklen_t l) { return 0; }
int __wrap_shutdown(int fd, int how) { return 0; }
int __wrap_chmod(const char *p, mode_t m) { return 0; }
int __wrap_chown(const char *p, uid_t u, gid_t g) { return 0; }
static struct passwd fake_pw = { (char *) "nobody", (char *) "x", 65534, 65534, (char *) "", (char *) "/", (char *) "/bin/false" };
static struct group fake_gr = { (char *) "nogroup", (char *) "x", 65534, NULL };
struct passwd *__wrap_getpwnam(const char *n) { return &fake_pw; }
struct group *__wrap_getgrnam(const char *n) { return &fake_gr; }

static char prefix[256];

static void
mkdir_p(const char *rel)
{
    char path[512];
    snprintf(path, sizeof(path), "%s%s", prefix, rel);
    mkdir(path, 0700);
}

static int
fuzz_init(void)
{
    ngx_cycle_t  init_cycle;
    char         conf[512], tmpl[256];
    const char  *td = getenv("TMPDIR");
    FILE        *f;
    static char *argv0[] = { (char *) "angie-fuzz", NULL };

    snprintf(tmpl, sizeof(tmpl), "%s/angie-fuzz-XXXXXX", (td && *td) ? td : "/tmp");
    if (mkdtemp(tmpl) == NULL) {
        perror("mkdtemp");
        abort();
    }
    snprintf(prefix, sizeof(prefix), "%s/", tmpl);
    mkdir_p("logs"); mkdir_p("tmp"); mkdir_p("html"); mkdir_p("html/static"); mkdir_p("html/inc");
    snprintf(conf, sizeof(conf), "%sangie.conf", prefix);
    f = fopen(conf, "w");
    fputs(configuration, f);
    fclose(f);
    snprintf(conf, sizeof(conf), "%shtml/index.html", prefix);
    f = fopen(conf, "w"); fputs("<html>index</html>\n", f); fclose(f);
    snprintf(conf, sizeof(conf), "%shtml/static/a.txt", prefix);
    f = fopen(conf, "w"); fputs("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", f); fclose(f);
    snprintf(conf, sizeof(conf), "%shtml/inc/a.html", prefix);
    f = fopen(conf, "w"); fputs("included <!--# echo var=\"uri\" -->\n", f); fclose(f);
    snprintf(conf, sizeof(conf), "%sangie.conf", prefix);

    ngx_debug_init();
    ngx_strerror_init();
    ngx_argv = ngx_os_argv = argv0;
    ngx_argc = 1;
    ngx_max_sockets = -1;
    ngx_time_init();
#if (NGX_PCRE)
    ngx_regex_init();
#endif
    ngx_pid = ngx_getpid();
    ngx_parent = ngx_getppid();

    fuzz_log.file = &fuzz_log_file;
    fuzz_log.log_level = NGX_LOG_EMERG;
    fuzz_log_file.fd = ngx_stderr;

#if (NGX_OPENSSL)
    ngx_ssl_init(&fuzz_log);
#endif

    ngx_memzero(&init_cycle, sizeof(ngx_cycle_t));
    init_cycle.log = &fuzz_log;
    ngx_cycle = &init_cycle;
    init_cycle.pool = ngx_create_pool(1024, &fuzz_log);

    init_cycle.prefix.data = (u_char *) prefix;
    init_cycle.prefix.len = strlen(prefix);
    init_cycle.conf_prefix = init_cycle.prefix;
    init_cycle.conf_file.data = (u_char *) strdup(conf);
    init_cycle.conf_file.len = strlen(conf);
    init_cycle.error_log.data = (u_char *) "stderr";
    init_cycle.error_log.len = 6;

    if (ngx_os_init(&fuzz_log) != NGX_OK) {
        abort();
    }
    ngx_crc32_table_init();
    ngx_slab_sizes_init();
    ngx_preinit_modules();

    cycle = ngx_init_cycle(&init_cycle);
    if (cycle == NULL) {
        fprintf(stderr, "angie-fuzz: ngx_init_cycle failed\n");
        abort();
    }
    ngx_cycle = cycle;
    cycle->log = &fuzz_log;

    ngx_event_actions.add = ev_add;
    ngx_event_actions.del = ev_del;
    ngx_event_actions.enable = ev_add;
    ngx_event_actions.disable = ev_del;
    ngx_event_actions.add_conn = NULL;
    ngx_event_actions.del_conn = NULL;
    ngx_event_actions.init = ev_init;
    ngx_event_flags = NGX_USE_LEVEL_EVENT;

    /* upstream connections get their I/O from ngx_io (ngx_event_connect_peer) */
    ngx_io.recv = upstream_recv;
    ngx_io.recv_chain = upstream_recv_chain;
    ngx_io.udp_recv = upstream_recv;
    ngx_io.send = fake_send;
    ngx_io.send_chain = fake_send_chain;
    ngx_io.flags = 0;
    return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    fuzz_init();
    return 0;
}

#define NCONN 4

static int
conn_closed(ngx_connection_t *c)
{
    return c->fd == (ngx_socket_t) -1;
}

/* re-initialise every shared zone exactly as ngx_init_cycle() did at startup */
static void
reset_shared_zones(void)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part = &cycle->shared_memory.part;
    ngx_shm_zone_t   *zn = part->elts;
    ngx_slab_pool_t  *sp;

    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            zn = part->elts;
            i = 0;
        }
        if (zn[i].shm.addr == NULL) {
            continue;
        }
        if (!zn[i].noslab) {
            sp = (ngx_slab_pool_t *) zn[i].shm.addr;
            sp->end = zn[i].shm.addr + zn[i].shm.size;
            sp->min_shift = 3;
            sp->addr = zn[i].shm.addr;
            ngx_slab_init(sp);
        }
        if (zn[i].init && zn[i].init(&zn[i], NULL) != NGX_OK) {
            fprintf(stderr, "angie-fuzz: re-initialising zone \"%.*s\" failed\n",
                    (int) zn[i].shm.name.len, zn[i].shm.name.data);
            abort();
        }
    }
}

static void
force_close(ngx_connection_t *c)
{
    ngx_pool_t *pool = c->pool;

    if (conn_closed(c)) {
        return;
    }
    c->destroyed = 1;
    ngx_close_connection(c);
    if (pool) {
        ngx_destroy_pool(pool);
    }
}

static void
fire_all_timers(void)
{
    ngx_rbtree_node_t  *node, *root, *sentinel;
    ngx_event_t        *ev;
    int                 guard = 0;

    sentinel = ngx_event_timer_rbtree.sentinel;
    while (guard++ < 256) {
        ngx_event_process_posted(cycle, &ngx_posted_next_events);
        ngx_event_process_posted(cycle, &ngx_posted_events);
        root = ngx_event_timer_rbtree.root;
        if (root == sentinel) {
            break;
        }
        node = ngx_rbtree_min(root, sentinel);
        ev = ngx_rbtree_data(node, ngx_event_t, timer);
        ngx_rbtree_delete(&ngx_event_timer_rbtree, &ev->timer);
        ev->timer_set = 0;
        ev->timedout = 1;
        ev->handler(ev);
    }
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ngx_connection_t  *conns, *c;
    ngx_event_t       *revs, *wevs;
    ngx_listening_t   *ls;
    int                i, j;
    static unsigned long n_forced;

#if FUZZ_MODE == FUZZ_HTTP
    {
        size_t k, sl = sizeof(reply_sep) - 1;
        client_in.data = data; client_in.len = size;
        upstream_in.data = data + size; upstream_in.len = 0;
        for (k = 0; k + sl <= size; k++) {
            if (memcmp(data + k, reply_sep, sl) == 0) {
                client_in.len = k;
                upstream_in.data = data + k + sl;
                upstream_in.len = size - k - sl;
                break;
            }
        }
    }
#elif IS_FILE_MODE(FUZZ_MODE)
    {
        /* the served file is the input; rewritten for every input */
        char  path[512];
        FILE *f;
        snprintf(path, sizeof(path), "%s%s", prefix, file_name);
        f = fopen(path, "wb");
        if (f == NULL) {
            abort();
        }
        if (size) {
            fwrite(data, 1, size, f);
        }
        fclose(f);
    }
    client_in.data = (const u_char *) file_request;
    client_in.len = sizeof(file_request) - 1;
    upstream_in.data = data + size; upstream_in.len = 0;
#elif IS_MAIL_PROXY_MODE(FUZZ_MODE)
    client_in.data = (const u_char *) mail_login;
    client_in.len = sizeof(mail_login) - 1;
    auth_in.data = (const u_char *) auth_reply;
    auth_in.len = sizeof(auth_reply) - 1;
    auth_fd = -1;
    upstream_in.data = data; upstream_in.len = size;
#elif IS_REPLY_MODE(FUZZ_MODE)
    client_in.data = (const u_char *) fixed_request;
    client_in.len = sizeof(fixed_request) - 1;
    upstream_in.data = data; upstream_in.len = size;
#else
    client_in.data = data; client_in.len = size;
    upstream_in.data = data + size; upstream_in.len = 0;
#endif

    ngx_time_update();
    reset_shared_zones();
    ngx_event_timer_init(&fuzz_log);
    ngx_queue_init(&ngx_posted_accept_events);
    ngx_queue_init(&ngx_posted_next_events);
    ngx_queue_init(&ngx_posted_events);

    conns = calloc(NCONN, sizeof(ngx_connection_t));
    revs = calloc(NCONN, sizeof(ngx_event_t));
    wevs = calloc(NCONN, sizeof(ngx_event_t));
    for (i = 0; i < NCONN; i++) {
        conns[i].read = &revs[i];
        conns[i].write = &wevs[i];
        conns[i].fd = (ngx_socket_t) -1;
        conns[i].data = (i + 1 < NCONN) ? &conns[i + 1] : NULL;
        revs[i].closed = 1;
        wevs[i].closed = 1;
    }
    cycle->free_connections = conns;
    cycle->free_connection_n = NCONN;

    ls = cycle->listening.elts;

    c = ngx_get_connection(open("/dev/null", O_RDWR), &fuzz_log);
    if (c == NULL) {
        abort();
    }
    c->type = SOCK_STREAM;
    c->pool = ngx_create_pool(ls->pool_size, &fuzz_log);
    c->sockaddr = ngx_palloc(c->pool, ls->socklen);
    ngx_memcpy(c->sockaddr, ls->sockaddr, ls->socklen);
    c->socklen = ls->socklen;
    c->local_sockaddr = ls->sockaddr;
    c->local_socklen = ls->socklen;
    c->listening = ls;
    c->log = &fuzz_log;
    c->recv = client_recv;
    c->send = fake_send;
    c->send_chain = fake_send_chain;
    c->recv_chain = upstream_recv_chain; /* not used by the client side */
    c->number = 1;
    c->start_time = ngx_current_msec;
    c->read->log = &fuzz_log;
    c->write->log = &fuzz_log;
    c->read->ready = 1;
    c->write->ready = 1;

    ls->handler(c);

    /*
     * Drive read events: first while the client keeps the connection open
     * (recv returns NGX_AGAIN once its bytes are consumed, so buffered
     * commands are still processed), then after the client closed it.
     */
    client_eof = 0;
    for (i = 0; i < 64 && !conn_closed(c); i++) {
        if (i == 16) {
            client_eof = 1;
        }
        ngx_event_process_posted(cycle, &ngx_posted_next_events);
        ngx_event_process_posted(cycle, &ngx_posted_events);
        if (conn_closed(c)) {
            break;
        }
        /* upstream side first: let it consume the rest of its reply */
        for (j = 0; j < NCONN; j++) {
            ngx_connection_t *u = &conns[j];
            if (u != c && !conn_closed(u) && !u->read->eof && u->read->handler) {
                u->read->ready = 1;
                u->read->handler(u->read);
            }
        }
        if (conn_closed(c)) {
            break;
        }
        c->read->ready = 1;
        if (c->read->handler) {
            c->read->handler(c->read);
        }
    }
    client_eof = 1;
    fire_all_timers();

    /*
     * Anything still open (no timer left to close it) is closed here:
     * upstream connections first, then the client.  ngx_close_connection()
     * also removes its timers and posted events, so the timer tree and the
     * posted queues are empty before the arrays are freed.
     */
    for (i = 0; i < NCONN; i++) {
        if (&conns[i] != c && !conn_closed(&conns[i])) {
            n_forced++;
            force_close(&conns[i]);
        }
    }
    if (!conn_closed(c)) {
        n_forced++;
        force_close(c);
    }
    if (getenv("ANGIE_FUZZ_DEBUG") && n_forced) {
        fprintf(stderr, "angie-fuzz: force-closed %lu connections so far\n", n_forced);
    }
    if (ngx_event_timer_rbtree.root != ngx_event_timer_rbtree.sentinel
        || !ngx_queue_empty(&ngx_posted_events)
        || !ngx_queue_empty(&ngx_posted_next_events))
    {
        fprintf(stderr, "angie-fuzz: events still pending after closing every connection\n");
        abort();
    }
    cycle->free_connections = NULL;
    cycle->free_connection_n = 0;
    free(conns); free(revs); free(wevs);
    return 0;
}
