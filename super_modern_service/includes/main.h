/*
 * Super modern service by d0now
 * for belluminar 2019
 * git : github.com/d0now/2019_belluminar
*/

#ifndef __MAIN_H__
#define __MAIN_H__

#define BINDER_SERVICE_SMS 0

#define SERVER_PORT 31447
#define CLIENT_COUNT 16

#define SVC_CREATE_SERVER       0x13370000
#define SVC_CREATE_CLIENT       0x13370001
#define SVC_CLOSE               0x13370002
#define SVC_CREATE_FILTER       0x13370003
#define SVC_FILTER_EDIT_DESC    0x13370004
#define SVC_FILTER_DUMP_DESC    0x13370005
#define SVC_CLIENT_RECV         0x13370006
#define SVC_CLIENT_SEND         0x13370007

uint16_t svcid[] = {
    's', 'u', 'p', 'e', 'r', '_', 
    'm', 'o', 'd', 'e', 'r', 'n', '_', 
    's', 'e', 'r', 'v', 'i', 'c', 'e'
};

struct connection {
    char name[64];
    int sock;
    int is_server;
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

int create_filter(struct connection *conn, const char *filter_ip, const char *filter_desc);
int filter_deletion(struct connection *conn, struct filter *filt);
int filter_cleanup(struct connection *conn);
int filter_free(struct filter *filt);
int filter_ref_inc(struct filter *filt);
int filter_ref_dec(struct filter *filt);
struct filter *filter_get_last(struct filter *filt);
struct filter *filter_get_head(struct filter *filt);
struct filter *filter_find(struct connection *conn, const char *filter_ip);
int filter_edit_desc(struct connection *conn, const char *filter_ip, const char *filter_desc);
int filter_dump_desc(struct connection *conn, const char *filter_ip, char *filter_desc);
int create_server(struct connection *server);
int create_client(struct connection *server, struct connection *client);
void *client_recv(struct connection *conn);
int client_send(struct connection *conn);
int close_connection(struct connection **p_conn);
#ifdef IO_BINDER
int service_handler(struct binder_state *bs,
                    struct binder_transaction_data *txn,
                    struct binder_io *msg,
                    struct binder_io *reply);
#else
int service_handler(void);
#endif

#endif