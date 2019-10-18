/*
 * Super modern service by d0now
 * for belluminar 2019
 * git : github.com/d0now/2019_belluminar
*/

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "binder.h"

#define BINDER_SERVICE_SMS 0

#define PING_TRANSACTION 0

#define SERVER_PORT 31447

#define CLIENT_COUNT 16

#define SVC_CREATE_SERVER   0x13370000
#define SVC_CREATE_CLIENT   0x13370001
#define SVC_CLOSE           0x13370002
#define SVC_CREATE_FILTER   0x13370003

uint16_t svcid[] = {
    's', 'u', 'p', 'e', 'r', '_', 
    'm', 'o', 'd', 'e', 'r', 'n', '_', 
    's', 'e', 'r', 'v', 'i', 'c', 'e'
};

struct connection {
    char name[64];
    int sock;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    struct filter *filters_head;
};

struct filter {
    struct filter *next;
    struct filter *prev;
    struct sockaddr_in addr;
    char desc[64];
    int refcount;
};

void filter_dump(struct filter *filt) {

    struct filter *now;

    for (now = filt ; now->next != NULL ; now = now->next) {
        printf("========================\n");
        printf("[%p, %p, %p]\n", now->prev, now, now->next);
        printf("refcount=%d\n", now->refcount);
    }
        printf("========================\n");
        printf("[%p, %p, %p]\n", now->prev, now, now->next);
        printf("refcount=%d\n", now->refcount);
    printf("========================\n");
}

int filter_free(struct filter *filt) {
    if (filt->refcount == 0)
        free(filt);
    else {
        fprintf(stderr, "Fatal: Detected double free\n");
        exit(0);
    }
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

    struct filter *now;

    if (filt == NULL)
        return 0;

    for (now = filt ; now->next != NULL ; now = now->next);
    if (now && now->next == NULL)
        return now;

    return 0;
}

struct filter *filter_get_head(struct filter *filt) {

    struct filter *now;

    if (filt == NULL)
        return 0;

    for (now = filt ; now->prev != NULL ; now = now->prev);
    if (now && now->next == NULL)
        return now;

    return 0;
}

int filter_deletion(struct connection *conn, struct filter *filt) {

    struct filter *now, *next, *prev;

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

int create_server(struct connection *server) {
    
    int sock;
    struct sockaddr_in server_addr;

    if (server == NULL)
        return -1;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        return -1;

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(SERVER_PORT);

    memset(server, 0, sizeof(*server));
    strncpy(server->name, "server", sizeof(server->name));
    server->sock = sock;
    memcpy(&server->server_addr, &server_addr, sizeof(server_addr));

    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        return -1;

    if (listen(sock, 16) < 0)
        return -1;

    return 0;
}

int create_client(struct connection *server, struct connection *client) {

    int sock, len;
    struct sockaddr_in client_addr;

    if (server == NULL || client == NULL)
        return -1;

    sock = accept(server->sock, (struct sockaddr *)&client_addr, &len);
    if (sock < 0) {
        fprintf(stderr, "error: accept\n");
        return -1;
    }

    memcpy(client, server, sizeof(*client));
    strncpy(client->name, "client", sizeof(client->name));
    client->sock = sock;
    memcpy(&client->client_addr, &client_addr, sizeof(client_addr));

    return 0;
}

int close_connection(struct connection **p_conn) {

    struct connection *conn;

    if (p_conn == NULL || *p_conn == NULL)
        return -1;

    conn = *p_conn;

    close(conn->sock);
    if (conn->filters_head)
        filter_cleanup(conn);

    *p_conn = NULL;

    return 0;
}

int create_filter(struct connection *conn,
                  const char *filter_ip, const char *filter_desc) {

    struct filter *filt, *prev;
    struct sockaddr_in filter_addr;

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

#ifdef IO_BINDER
int service_handler(struct binder_state *bs,
                    struct binder_transaction_data *txn,
                    struct binder_io *msg,
                    struct binder_io *reply) {

    uint32_t strict_policy;
    uint16_t *s;
    size_t len;

    if (txn->target.ptr != BINDER_SERVICE_SMS)
        return -1;

    if (txn->code == 0)
        return 0;

    strict_policy = bio_get_uint32(msg);
    s = bio_get_string16(msg, &len);
    if (s == NULL)
        return -1;

    if ((len != (sizeof(svcid) / 2)) ||
        memcmp(svcid, s, sizeof(svcid))) {
        return -1;
    }

    switch (txn->code) {
        default:
            return -1;
    }

    bio_put_uint32(reply, 0);
    return 0;
}

int main(int argc, const char *argv[], const char *envp[]) {

    struct binder_state *bs;

    bs = binder_open("/dev/binder", 128*1024);
    if (bs == NULL) {
        fprintf(stderr, "error: cannot open binder driver.\n");
        return -1;
    }

    if (binder_become_context_manager(bs)) {
        fprintf(stderr, "error: binder_become_context_manager failed(%s).\n", strerror(errno));
        return -1;
    }

    binder_loop(bs, service_handler);
    return 0;
}

#else
int service_handler(void) {

    int cmd, idx, idx2;
    char buf[16];

    struct connection *conn[32];

    memset(conn, 0, sizeof(struct connection));

    while (1) {

        printf("> ");
        fgets(buf, 16, stdin);
        cmd = atoi(buf);

        switch (cmd) {

            case SVC_CREATE_SERVER & 0xffff:
                printf("idx> ");
                fgets(buf, 16, stdin);
                idx = atoi(buf);
                conn[idx] = malloc(sizeof(struct connection));
                if (create_server(conn[idx])) {
                    fprintf(stderr, "server creation failed.\n");
                    free(conn[idx]);
                    conn[idx] = NULL;
                }
                break;

            case SVC_CREATE_CLIENT & 0xffff:
                printf("idx> ");
                fgets(buf, 16, stdin);
                idx = atoi(buf);
                printf("idx2> ");
                fgets(buf, 16, stdin);
                idx2 = atoi(buf);
                conn[idx2] = malloc(sizeof(struct connection));
                if (create_client(conn[idx], conn[idx2])) {
                    fprintf(stderr, "client creation failed.\n");
                    free(conn[idx2]);
                    conn[idx2] = NULL;
                }
                break;

            case SVC_CLOSE & 0xffff:
                printf("idx> ");
                fgets(buf, 16, stdin);
                idx = atoi(buf);
                if (close_connection(&conn[idx]))
                    fprintf(stderr, "closing failed.\n");
                break;

            case SVC_CREATE_FILTER & 0xffff:
                printf("idx> ");
                fgets(buf, 16, stdin);
                idx = atoi(buf);
                if (create_filter(conn[idx], "192.168.0.1", "Hello, World!"))
                    fprintf(stderr, "filter creation failed.\n");
                break;

            default:
                printf("Bye...\n");
                return 0;
        }

        printf("Done\n");
    }
}

int main(int argc, const char *argv[], const char *envp[]) {
    service_handler();
}

#endif
