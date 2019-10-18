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

#include "binder.h"

#define BINDER_SERVICE_SMS 0

#define PING_TRANSACTION 0

#define SERVER_PORT 31447

#define CLIENT_COUNT 16

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
};

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

int filter_cleanup(struct filter *filt) {

    struct filter *now;

    if (filt == NULL)
        return -1;

    for (now = filt->next ; now->next != NULL ; now = now->next)
        free(now->prev);
    free(now);

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
    struct filter *filt, *prev;

    if (server == NULL || client == NULL)
        return -1;

    sock = accept(server->sock, (struct sockaddr *)&client_addr, &len);
    if (sock < 0)
        return -1;

    memcpy(client, server, sizeof(*client));
    strncpy(client->name, "client", sizeof(client->name));
    client->sock = sock;
    memcpy(&client->client_addr, &client_addr, sizeof(client_addr));

    /*
    if ((filt = malloc(sizeof(filt))) == NULL)
        return -1;

    if (server->filters_head) {
        prev = filter_get_last(server->filters_head);
        prev->next = filt;
        filt->prev = prev;
    }
    else
        server->filters_head = filt;

    memcpy(&filt->addr, &client_addr, sizeof(client_addr));
    strncpy(filt->desc, "Description", sizeof(filt->desc));
    */

    return 0;
}

int close_connection(struct connection *) {
    close(connection->sock);
    if (connection->filters_head)
        filter_cleanup(filters_head);
}

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