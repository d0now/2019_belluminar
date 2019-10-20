/*
 * Super modern service by d0now
 * for belluminar 2019
 * git : github.com/d0now/2019_belluminar
*/

#include "main.h"
#include "logger.h"
#include "binder.h"

char *string(size_t len) {

    char *ret;

    LOG_VA("string(%lx) = ", len);
    ret = calloc(len, 1);
    LOG_VA("%p;\n", ret);

    return ret;
}

uint16_t *string16(size_t len) {

    uint16_t *ret;

    LOG_VA("string16(%lx) = ", len);
    ret = calloc(len, 2);
    LOG_VA("%p;\n", ret);

    return ret;
}

int string_free(void *ptr) {

    LOG_VA("string_free(%p);\n", ptr);
    if (ptr)
        free(ptr);
}

char *string16_to_string(const uint16_t *string16, size_t len) {

    char *ret = NULL;
    int i;

    LOG_VA("string16_to_string(%p, %lx) = ", string16, len);

    if (string16 == NULL)
        goto done;

    if ((ret = string(len)) == NULL)
        goto done;

    for (i=0 ; i<len ; i++)
        ret[i] = (char)string16[i];

done:
    LOG_VA("%p;\n", ret);
    return ret;
}

uint16_t *string_to_string16(const char *string, size_t len) {

    uint16_t *ret = NULL;
    int i;

    LOG_VA("string_to_string16(%p, %lx) = ", string16, len);

    if (string == NULL)
        goto done;

    if ((ret = string16(len)) == NULL)
        goto done;

    for (i=0 ; i<len ; i++)
        ret[i] = (uint16_t)string[i];

done:
    LOG_VA("%p;\n", ret);
    return ret;
}

int fd_is_valid(int fd) {
    return fcntl(fd, F_GETFD) != -1 || errno != EBADF;
}

int create_filter(struct connection *conn,
                  const char *filter_ip, const char *filter_desc) {

    struct filter *filt, *prev;
    struct sockaddr_in filter_addr;

    LOG_VA("create_filter(%p, \"%s\", \"%s\");\n", conn, filter_ip, filter_desc);
    LOG_VA("size=%lx\n", sizeof(struct filter));

    if (conn == NULL || filter_ip == NULL || filter_desc == NULL)
        return -1;

    memset(&filter_addr, 0, sizeof(filter_addr));
    if (inet_pton(AF_INET, filter_ip, &(filter_addr.sin_addr)) != 1)
        return -1;

    if ((filt = calloc(sizeof(*filt), 1)) == NULL)
        return -1;

    if (conn->filters_head) {
        prev = filter_get_last(conn->filters_head);
        filt->prev = prev;
        prev->next = filt;
        filter_ref_inc(filt);
        filter_ref_inc(prev);
    }
    else {
        conn->filters_head = filt;
        filter_ref_inc(filt);
    }

    memcpy(&filt->addr, &filter_addr, sizeof(filt->addr));
    strncpy(filt->desc, filter_desc, sizeof(filt->desc));

    return 0;
}

int filter_deletion(struct connection *conn, struct filter *filt) {

    struct filter *now, *next, *prev;

    LOG_VA("filter_deletion(%p, %p);\n", conn, filt);

    if (filt == NULL)
        return -1;

    now  = filt;
    next = filt->next;
    prev = filt->prev;

    if (next && prev) {
        next->prev = prev;
        prev->next = next;
        filter_ref_dec(now);
        filter_ref_dec(now);
    }
    else if (next == NULL && prev) {
        prev->next = next;
        filter_ref_dec(now);
    }
    else if (next && prev == NULL) {
        conn->filters_head = next;
        next->prev = NULL;
        filter_ref_dec(now);
        filter_ref_dec(now);
    }
    else {
        conn->filters_head = NULL;
        filter_ref_dec(now);
    }

    filter_free(now);

    return 0;
}

int filter_cleanup(struct connection *conn) {

    struct filter *filt, *now, *next;

    LOG_VA("filter_cleanup(%p);\n", conn);

    if (conn == NULL)
        return -1;

    filt = conn->filters_head;

    if (filt == NULL)
        return -1;

    if (filt->next) {
        filt = filter_get_last(filt);
        for (now = filt->prev ; now->prev != NULL ; now = now->prev) {
            next = now->next;
            next->prev = NULL;
            filter_ref_dec(now);
            now->next = NULL;
            filter_ref_dec(next);
            filter_free(next);
        }
        next = now->next;
        next->prev = NULL;
        filter_ref_dec(now);
        now->next = NULL;
        filter_ref_dec(next);
        filter_free(next);
    }
    filt = conn->filters_head;
    conn->filters_head = NULL;
    filter_ref_dec(filt);
    filter_free(filt);

    return 0;
}

int filter_free(struct filter *filt) {

    LOG_VA("filter_free(%p);\n", filt);

    if (filt->refcount == 0)
        free(filt);
    else {
        logger_write("Fatal: Detected double free\n");
        exit(0);
    }

    return 0;
}

int filter_ref_inc(struct filter *filt) {
    return filt->refcount++;
}

int filter_ref_dec(struct filter *filt) {
    if (filt->refcount)
        filt->refcount--;
    return filt->refcount;
}

struct filter *filter_get_last(struct filter *filt) {

    struct filter *ret = NULL;
    struct filter *now;

    LOG_VA("filter_get_last(%p) = ", filt);

    if (filt == NULL)
        goto done;

    for (now = filt ; now->next != NULL ; now = now->next);
    if (now && now->next == NULL)
        ret = now;

done:
    LOG_VA("%p;\n", ret);
    return ret;
}

struct filter *filter_get_head(struct filter *filt) {

    struct filter *ret = NULL;
    struct filter *now;

    LOG_VA("filter_get_head(%p) = ", filt);

    if (filt == NULL)
        goto done;

    for (now = filt ; now->prev != NULL ; now = now->prev);
    if (now && now->next == NULL)
        ret = now;

done:
    LOG_VA("%p;\n", ret);
    return ret;
}

int filter_check(struct connection *conn, struct sockaddr_in *addr) {

    int found;
    struct filter *now;

    LOG_VA("filter_check(%p, %p);\n", conn, addr);

    found = 0;

    if (conn == NULL || addr == NULL)
        goto done;

    for (now = conn->filters_head ; now->next != NULL ; now = now->next) {
        if (now->addr.sin_addr.s_addr == addr->sin_addr.s_addr) {
            found = 1;
            break;
        }
    }
    if (now->addr.sin_addr.s_addr == addr->sin_addr.s_addr)
        found = 1;

done:
    return found;
}

struct filter *filter_find(struct connection *conn, const char *filter_ip) {

    struct filter *ret = NULL;
    struct filter *now;
    struct sockaddr_in filter_addr;
    int found;

    LOG_VA("filter_find(%p, \"%s\") = ", conn, filter_ip);

    if (conn == NULL || filter_ip == NULL)
        goto done;

    memset(&filter_addr, 0, sizeof(filter_addr));
    if (inet_pton(AF_INET, filter_ip, &(filter_addr.sin_addr)) != 1)
        goto done;

    for (now = conn->filters_head ; now->next != NULL ; now = now->next) {
        if (now->addr.sin_addr.s_addr == filter_addr.sin_addr.s_addr) {
            found = 1;
            break;
        }
    }
    if (now->addr.sin_addr.s_addr == filter_addr.sin_addr.s_addr)
        found = 1;

    if (found)
        ret = now;

done:
    LOG_VA("%p;\n", now);
    return ret;
}

int filter_delete(struct connection *conn, const char *filter_ip) {

    struct filter *filt;
    struct sockaddr_in filter_addr;

    LOG_VA("filter_delete(%p, \"%s\");", conn, filter_ip);

    if (conn == NULL || filter_ip == NULL)
        return -1;

    if ((filt = filter_find(conn, filter_ip)) == NULL)
        return -1;

    return filter_deletion(conn, filt);
}

int filter_edit_desc(struct connection *conn, const char *filter_ip, const char *filter_desc) {

    struct filter *filt;

    LOG_VA("filter_edit_desc(%p, \"%s\", \"%10s\");\n", conn, filter_ip, filter_desc);

    if (conn == NULL || filter_ip == NULL || filter_desc == NULL)
        return -1;

    if ((filt = filter_find(conn, filter_ip)) == NULL)
        return -1;

    strncpy(filt->desc, filter_desc, sizeof(filt->desc));
    LOG_VA("strlen(\"%s\")=%lx\n", filt->desc, strlen(filt->desc));
    return 0;
}

int filter_dump_desc(struct connection *conn, const char *filter_ip, char *filter_desc) {

    struct filter *filt;

    LOG_VA("filter_dump_desc(%p, \"%s\", %p);\n", conn, filter_ip, filter_desc);

    if (conn == NULL || filter_ip == NULL || filter_desc == NULL)
        return -1;

    if ((filt = filter_find(conn, filter_ip)) == NULL)
        return -1;

    strncpy(filter_desc, filt->desc, sizeof(filt->desc));
    return 0;
}

int client_recv(struct connection *conn, void *data, size_t *size) {

    int r;

    LOG_VA("client_recv(%p, %p, %p);\n", conn, data, size);

    if (conn == NULL || conn->is_server)
        return -1;

    if (data == NULL || size == NULL)
        return -1;

    LOG_VA("read(conn->sock, %p, %lx);\n", size, sizeof(*size));
    r = read(conn->sock, size, sizeof(*size));
    if (r != sizeof(*size)) {
        *size = 0;
        return -1;
    }

    if (*size < 0 && *size > 0x1000)
        *size = 0x1000;

    LOG_VA("size=%lx\n", *size);

    r = read(conn->sock, data, *size);
    if (r != *size)
        return -1;

    LOG_VA("read(conn->sock, %p, %lx);\n", data, *size);

    return 0;
}

int client_send(struct connection *conn, void *data, size_t size) {

    int r;

    LOG_VA("client_send(%p, %p, %lx);\n", conn, data, size);
    
    if (conn == NULL || data == NULL)
        return -1;

    if (size < 0 && size > 0x1000)
        size = 0x1000;

    r = write(conn->sock, &size, sizeof(size));
    if (r != sizeof(size))
        return -1;

    r = write(conn->sock, data, size);
    if (r != size)
        return -1;

    return 0;
}

int create_server(struct connection *server) {
    
    int sock;
    struct sockaddr_in server_addr;

    LOG_VA("create_server(%p);\n", server);

    if (server == NULL) {
        LOG_VA("error: server is null.\n");
        return -1;
    }

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        LOG_VA("error: can't create socket.\n");
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(SERVER_PORT);

    memset(server, 0, sizeof(*server));
    strncpy(server->name, "server", sizeof(server->name));
    server->sock = sock;
    memcpy(&server->server_addr, &server_addr, sizeof(server_addr));

    server->is_server = 1;

    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        LOG_VA("error: can't bind.\n");
        return -1;
    }

    if (listen(sock, 16) < 0) {
        LOG_VA("error: can't listen.\n");
        return -1;
    }

    return 0;
}

int create_client(struct connection *server, struct connection *client) {

    int sock, len;
    struct sockaddr_in client_addr;

    LOG_VA("create_client(%p, %p);\n", server, client);

    if (server == NULL || client == NULL)
        return -1;

    sock = accept(server->sock, (struct sockaddr *)&client_addr, &len);
    if (sock < 0) {
        logger_write("error: accept\n");
        return -1;
    }

    if (filter_check(server, &client_addr)) {
        logger_write("error: filterd.\n");
        return -1;
    }

    memcpy(client, server, sizeof(*client));
    strncpy(client->name, "client", sizeof(client->name));
    memcpy(&client->client_addr, &client_addr, sizeof(client_addr));
    client->sock = sock;
    client->is_server = 0;

    return 0;
}

int close_connection(struct connection **p_conn) {

    struct connection *conn;

    LOG_VA("close_connection(%p);\n", p_conn);

    if (p_conn == NULL || *p_conn == NULL)
        return -1;

    conn = *p_conn;

    close(conn->sock);
    if (conn->filters_head)
        filter_cleanup(conn);

    *p_conn = NULL;

    return 0;
}

struct connection *conn[CONNECTION_COUNT];
int service_handler(struct binder_state *bs,
                    struct binder_transaction_data *txn,
                    struct binder_io *msg,
                    struct binder_io *reply) {

    uint32_t strict_policy;
    uint16_t *s, *s1, *s2;
    char *str1, *str2;
    size_t len1, len2;
    void *data, *bio_data;

    uint32_t idx1, idx2;

    LOG_VA("service_handler(%p, %p, %p, %p);\n", bs, txn, msg, reply);

    if (txn->target.ptr != BINDER_SERVICE_SMS)
        return -1;

    if (txn->code == 0)
        return 0;

    strict_policy = bio_get_uint32(msg);
    s = bio_get_string16(msg, &len1);
    if (s == NULL)
        return -1;

    if ((len1 != (sizeof(svc_sms_id) / 2)) ||
        memcmp(svc_sms_id, s, sizeof(svc_sms_id))) {
        return -1;
    }

    logger_write("cmd executing...\n");
    switch (txn->code) {

        case SVC_CREATE_SERVER:

            idx1 = bio_get_uint32(msg);
            if (idx1 < 0 || idx1 > CONNECTION_COUNT) {
                logger_write("indexing failed.\n");
                goto err;
            }

            conn[idx1] = malloc(sizeof(struct connection));
            if (conn[idx1] == NULL) {
                logger_write("malloc failed.\n");
                goto err;
            }

            if (create_server(conn[idx1])) {
                logger_write("server creation failed.\n");
                free(conn[idx1]);
                conn[idx1] = NULL;
                goto err;
            }

            logger_write("server created.\n");
            break;

        case SVC_CREATE_CLIENT:

            idx1 = bio_get_uint32(msg);
            idx2 = bio_get_uint32(msg);
            if ((idx1 < 0 || idx1 >= CONNECTION_COUNT) ||
                (idx2 < 0 || idx2 >= CONNECTION_COUNT)) {
                logger_write("indexing failed.\n");
                goto err;
            }

            if (conn[idx1] == NULL) {
                logger_write("server not exist.\n");
                goto err;
            }

            conn[idx2] = malloc(sizeof(struct connection));
            if (conn[idx2] == NULL) {
                logger_write("malloc failed.\n");
                goto err;
            }

            if (create_client(conn[idx1], conn[idx2])) {
                logger_write("client creation failed.\n");
                free(conn[idx2]);
                conn[idx2] = NULL;
                goto err;
            }

            logger_write("client created.\n");
            break;

        case SVC_CLOSE:

            idx1 = bio_get_uint32(msg);
            if (idx1 < 0 || idx1 >= CONNECTION_COUNT) {
                logger_write("indexing failed.\n");
                goto err;
            }

            if (conn[idx1] == NULL) {
                logger_write("connection not exist.\n");
                goto err;
            }

            if (close_connection(&conn[idx1])) {
                logger_write("closing failed.\n");
                goto err;
            }

            logger_write("connection closed.\n");
            break;

        case SVC_CREATE_FILTER:

            idx1 = bio_get_uint32(msg);
            s1 = bio_get_string16(msg, &len1);
            s2 = bio_get_string16(msg, &len2);
            if (idx1 < 0 || idx1 >= CONNECTION_COUNT || s1 == NULL || s2 == NULL) {
                logger_write("indexing failed.\n");
                goto err;
            }

            if (conn[idx1] == NULL) {
                logger_write("connection not exist.\n");
                goto err;
            }

            str1 = string16_to_string(s1, len1);
            str2 = string16_to_string(s2, len2);
            if (str1 == NULL || str2 == NULL) {
                logger_write("conversion failed.\n");
                goto err;
            }

            if (create_filter(conn[idx1], str1, str2)) {
                logger_write("filter creation failed.\n");
                goto err;
            }

            string_free(str1);
            string_free(str2);

            logger_write("filter created.\n");
            break;

        case SVC_DELETE_FILTER:

            idx1 = bio_get_uint32(msg);
            s1 = bio_get_string16(msg, &len1);
            if (idx1 < 0 || idx1 >= CONNECTION_COUNT || s1 == NULL) {
                logger_write("indexing failed.\n");
                goto err;
            }

            if (conn[idx1] == NULL) {
                logger_write("connection not exist.\n");
                goto err;
            }

            str1 = string16_to_string(s1, len1);
            if (str1 == NULL || str2 == NULL) {
                logger_write("conversion failed.\n");
                goto err;
            }

            if (filter_delete(conn[idx1], str1)) {
                logger_write("filter deletion failed.\n");
                goto err;
            }

            string_free(str1);

            logger_write("filter deleted.\n");
            break;

        case SVC_FILTER_EDIT_DESC:

            idx1 = bio_get_uint32(msg);
            s1 = bio_get_string16(msg, &len1);
            s2 = bio_get_string16(msg, &len2);
            if (idx1 < 0 || idx1 >= CONNECTION_COUNT) {
                logger_write("indexing failed.\n");
                goto err;
            }

            if (s1 == NULL || s2 == NULL) {
                logger_write("argument error.\n");
                goto err;
            }

            if (conn[idx1] == NULL) {
                logger_write("connection not exist.\n");
                goto err;
            }

            str1 = string16_to_string(s1, len1);
            str2 = string16_to_string(s2, len2);
            if (str1 == NULL || str2 == NULL) {
                logger_write("conversion failed.\n");
                goto err;
            }

            if (filter_edit_desc(conn[idx1], str1, str2)) {
                logger_write("editing failed.\n");
                goto err;
            }

            string_free(str1);
            string_free(str2);

            logger_write("filter edited.\n");
            break;

        case SVC_FILTER_DUMP_DESC:

            idx1 = bio_get_uint32(msg);
            s1 = bio_get_string16(msg, &len1);
            if (idx1 < 0 || idx1 >= CONNECTION_COUNT) {
                logger_write("indexing failed.\n");
                goto err;
            }

            if (s1 == NULL) {
                logger_write("argument error.\n");
                goto err;
            }

            if (conn[idx1] == NULL) {
                logger_write("connection not exist.\n");
                goto err;
            }

            str1 = string16_to_string(s1, len1);
            str2 = string(sizeof(((struct filter *)0)->desc));
            if (str1 == NULL || str2 == NULL) {
                logger_write("conversion failed.\n");
                string_free(str1);
                string_free(str2);
                goto err;
            }

            if (filter_dump_desc(conn[idx1], str1, str2)) {
                logger_write("dump failed.\n");
                string_free(str1);
                string_free(str2);
                goto err;
            }

            bio_put_uint32(reply, 0);
            bio_put_string16_x(reply, str2);
            string_free(str1);
            string_free(str2);

            logger_write("filter dumped.\n");
            return 0;
            break;

        case SVC_CLIENT_RECV:

            idx1 = bio_get_uint32(msg);
            if (idx1 < 0 || idx1 >= CONNECTION_COUNT) {
                logger_write("indexing failed.\n");
                goto err;
            }

            if (conn[idx1] == NULL) {
                logger_write("connection not exist.\n");
                goto err;
            }

            if ((data = malloc(0x1000)) == NULL) {
                logger_write("malloc failed.\n");
                goto err;
            }

            if (client_recv(conn[idx1], data, &len1)) {
                logger_write("recv failed.\n");
                goto err;
            }

            bio_put_uint32(reply, 0);
            bio_put_uint32(reply, len1);

            if ((bio_data = bio_alloc(reply, len1)) == NULL) {
                logger_write("bio_alloc failed.\n");
                goto err;
            }
            memcpy(bio_data, data, len1);
            free(data);
            return 0;
            break;

        case SVC_CLIENT_SEND:

            idx1 = bio_get_uint32(msg);
            if (idx1 < 0 || idx1 >= CONNECTION_COUNT) {
                logger_write("indexing failed.\n");
                goto err;
            }

            if (conn[idx1] == NULL) {
                logger_write("connection not exist.\n");
                goto err;
            }

            len1 = bio_get_uint32(msg);
            if (len1 < 0 || len1 > 0x1000)
                len1 = 0x1000;

            bio_data = bio_get(msg, len1);
            if (bio_data == NULL || len1 == 0) {
                logger_write("get binder buffer failed.\n");
                goto err;
            }

            data = malloc(len1);
            if (data == NULL)
                goto err;

            memcpy(data, bio_data, len1);

            if (!fd_is_valid(conn[idx1]->sock) || 
                client_send(conn[idx1], data, len1)) {
                logger_write("send failed.\n");
                goto err;
            }

            free(data);
            break;

        default:
            return -1;
    }

    bio_put_uint32(reply, 0);
    return 0;
err:
    bio_put_uint32(reply, -1);
    return -1;
}

int main(int argc, const char *argv[], const char *envp[]) {

    struct binder_state *bs;

    logger_init("/tmp/log.txt");
    signal(SIGPIPE, SIG_IGN);

    bs = binder_open("/dev/binder", 128*1024);
    if (bs == NULL) {
        logger_write("error: cannot open binder driver.\n");
        return -1;
    }

    if (binder_become_context_manager(bs)) {
        logger_write("error: binder_become_context_manager failed.\n");
        return -1;
    }

    logger_write("Looping...\n");
    binder_loop(bs, service_handler);
    return 0;
}