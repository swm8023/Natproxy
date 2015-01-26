#include <oh.h>
#include <stdio.h>
#include <stdlib.h>

#define STATUS_OK  0
#define STATUS_NOK 1
#define STATUS_RCN 2

#define BUFSZ 65536

#define PACKOP_DATA  0
#define PACKOP_CLOSE 1
#define PACKOP_SETMP 2
#define PACKOP_KEEP  3

typedef struct _tag_client_cfg {
    net_addr addr;
    int mapport;
    tcp_client client;
    int status;
    evt_timer rcn_ev;
    evt_timer keep_ev;
} client_cfg;

typedef struct _tag_nat_client{
    client_cfg *ccfg;
    tcp_client *client;
    int id;
    int bt;
    int closeflag;
    ohbuffer cache;

} nat_client;

net_addr servaddr;

map_t *portcfg_map;
map_t *client_map;

void on_cc_connect(tcp_client *client);
void on_cc_read(tcp_client *client);
void on_cc_close(tcp_client *client);

void on_ss_connect(tcp_client *client);
void on_ss_read(tcp_client *client);
void on_ss_close(tcp_client *client);

void complete_package_head(char* pack, int len, char op) {
    memcpy(pack, (char*)&len, 4);
    pack[4] = op;
}

tcp_client* find_client_byid(int id) {
    if (!iter_equal(map_find(client_map, id), map_end(client_map))) {
        return *(tcp_client**)map_at(client_map, id);
    } else {
        return NULL;
    }
}


int client_parse_cfg(const char *fname) {
    FILE *fp = fopen(fname, "rb");
    struct xml_document* doc = xml_open_document(fp);
    if (doc == NULL) {
        log_fatal("parse xml config file failed!");
    }
    struct xml_node* root = xml_document_root(doc);

    /* init server */
    uint8_t *servaddr_s = xml_easy_content(xml_easy_child(root, "server-addr", 0));
    uint8_t *servport_s = xml_easy_content(xml_easy_child(root, "server-port", 0));
    netaddr_init_v4(&servaddr, servaddr_s, strtol(servport_s, NULL, 10));

    log_debug("serv addr:  %s:%d", servaddr_s, strtol(servport_s, NULL, 10));

    /* init mappings */
    int i;
    int clientnum = xml_node_children(xml_easy_child(root, "port-mappings", 0));
    for (i = 0; i < clientnum; i++) {
        struct xml_node *mnode = xml_node_child(xml_easy_child(root, "port-mappings", 0), i);
        if (mnode == NULL) {
            log_fatal("parse xml config file failed!");
        }
        client_cfg *ccfg = (client_cfg*)ohmalloc(sizeof(client_cfg));
        memset(ccfg, 0, sizeof(client_cfg));

        uint8_t *cliaddr_s = xml_easy_content(xml_easy_child(mnode, "client-addr", 0));
        uint8_t *cliport_s = xml_easy_content(xml_easy_child(mnode, "client-port", 0));
        uint8_t *mapport_s = xml_easy_content(xml_easy_child(mnode, "mapping-port", 0));
        netaddr_init_v4(&ccfg->addr, cliaddr_s, strtol(cliport_s, NULL, 10));
        ccfg->mapport = strtol(mapport_s, NULL, 10);
        ccfg->status = STATUS_NOK;
        map_put(portcfg_map, (int)strtol(mapport_s, NULL, 10), ccfg);

        log_debug("mapping %d:  %s:%d => %d", i, cliaddr_s, strtol(cliport_s, NULL, 10), strtol(mapport_s, NULL, 10));

    }
}

void cc_timer_keep(evt_loop *loop, evt_timer *ev) {
    tcp_client* client = (tcp_client*)ev->data;
    client_cfg *ccfg = (client_cfg*)client->data;
    char pack[BUFSZ];
    complete_package_head(pack, 9, PACKOP_KEEP);
    memcpy(pack + 5, (char*)&ccfg->mapport, 4);
    tcp_send(client, pack, 9);
}

/* client to LAN */
void on_ss_connect(tcp_client *client) {
    nat_client *nc = (nat_client*)client->data;
    char tmp[BUFSZ];

    if (client->flag & TCPFLG_CLT_CONNFAIL) {
        tcp_close(client);
        return;
    } else {
        log_info("ss %d connect", nc->id);

        /* send cached data*/
        while (buf_used(&nc->cache)) {
            int n = buf_readall(&nc->cache, tmp, BUFSZ);
            tcp_send(client, tmp, n);
        }
    }
}

void on_ss_read(tcp_client *client) {
    nat_client *nc = (nat_client*)client->data;
    char tmp[BUFSZ];
    ohbuffer *rbuf = &client->rbuf;
    /* send data to server */
    while (buf_used(rbuf)) {
        int n = buf_readall(rbuf, tmp + 9, BUFSZ - 9);
        nc->bt += n;
        if (nc->ccfg->status == STATUS_OK) {
            complete_package_head(tmp, n + 9, PACKOP_DATA);
            memcpy(tmp + 5, (char*)&nc->id, 4);
            tcp_send(&nc->ccfg->client, tmp, n + 9);
        }
    }
}

void on_ss_close(tcp_client *client) {
    nat_client *nc = (nat_client*)client->data;
    char tmp[BUFSZ];
    /* close by local, send to remote */
    if (nc->closeflag == 0 && nc->ccfg->status == STATUS_OK) {
        complete_package_head(tmp, 9, PACKOP_CLOSE);
        memcpy(tmp + 5, (char*)&nc->id, 4);
        tcp_send(&nc->ccfg->client, tmp, 9);
        log_info("ss %d send close(data %d)", nc->id, nc->bt);
    } else {
        log_info("ss %d recv close(data %d)", nc->id, nc->bt);
    }
    map_erase_val(client_map, nc->id);
    buf_destroy(&nc->cache);
    ohfree(nc);
}

/* client to WAN */
void on_cc_connect(tcp_client *client) {
    client_cfg *ccfg = (client_cfg*)client->data;

    if (client->flag & TCPFLG_CLT_CONNFAIL) {
        log_info("cc %d connect failed", ccfg->mapport);
        tcp_close(client);
        return;
    } else if (client->flag & TCPFLG_CLT_CONNED) {
        ccfg->status = STATUS_OK;
        log_info("cc %d connect success", ccfg->mapport);

        /* send mapping port as connection id */
        char pack[BUFSZ];
        complete_package_head(pack, 9, PACKOP_SETMP);
        memcpy(pack + 5, (char*)&ccfg->mapport, 4);
        tcp_send(client, pack, 9);

        /* keep alive */
        evt_timer_init(&ccfg->keep_ev, cc_timer_keep, SECOND(10), SECOND(10));
        evt_set_data(&ccfg->keep_ev, client);
        evt_timer_start(client->loop_on, &ccfg->keep_ev);
    }
}

void on_cc_read(tcp_client *client) {
    ohbuffer *rbuf = &client->rbuf;
    client_cfg *ccfg = (client_cfg*)client->data;
    char tmp[BUFSZ];

    /* the shortest package length is 9 */
    while (buf_used(rbuf) >= 9) {
        /* read head and opid */
        int len, opid;
        buf_peek(rbuf, 9, tmp, BUFSZ);
        memcpy(&len, tmp, 4);
        memcpy(&opid, tmp + 5, 4);
        char op = tmp[4];

        /* data in package not enough */
        if (buf_used(rbuf) < len) {
            return;
        }
        buf_read(rbuf, 9, tmp, BUFSZ);
        /* data */
        if (op == PACKOP_DATA) {
            tcp_client *nclient = find_client_byid(opid);
            len -= 9;
            buf_read(rbuf, len, tmp, BUFSZ);
            /* no this client, create now */
            if (nclient == NULL) {
                nclient = (tcp_client*)ohmalloc(sizeof(tcp_client));
                tcp_client_init(nclient, &ccfg->addr, client->loop_on, 0, NULL, 0);
                tcp_connection_set_on_close(nclient, on_ss_close);
                tcp_connection_set_on_read(nclient, on_ss_read);
                tcp_connection_set_on_connect(nclient, on_ss_connect);
                tcp_connect(nclient);
                map_put(client_map, opid, nclient);

                nat_client *nc = (nat_client*)ohmalloc(sizeof(nat_client));
                nc->client = client;
                nc->ccfg = ccfg;
                nc->id = opid;
                nc->bt = 0;
                nc->closeflag = 0;
                buf_init(&nc->cache, OHBUFFER_UNIT_DEFAULT_SIZE, NULL, 0);

                nclient->data = nc;

                buf_write(&nc->cache, tmp, len);
            /* exist but not connect success now */
            } else if (0 == (nclient->flag & TCPFLG_CLT_CONNED)) {
                nat_client *nc = (nat_client*)nclient->data;
                buf_write(&nc->cache, tmp, len);
            /* connected, send data directly */
            } else {
                tcp_send(nclient, tmp, len);
            }
        /* close command */
        } else if (op == PACKOP_CLOSE) {
            tcp_client *nclient = find_client_byid(opid);
            if (nclient) {
                nat_client *nc = (nat_client*)nclient->data;
                nc->closeflag = 1;
                tcp_close(nclient);
            } else {
                log_info("nclient is null when recv close");
            }

        } else {
            log_fatal("error operation");
        }

    }
}

void cc_reconn(evt_loop *loop, evt_timer *ev) {
    client_cfg *ccfg = (client_cfg*)ev->data;
    tcp_client_init(&ccfg->client, &servaddr, loop, 0, NULL, 0);
    ccfg->client.data = ccfg;

    tcp_connection_set_on_close(&ccfg->client, on_cc_close);
    tcp_connection_set_on_read(&ccfg->client, on_cc_read);
    tcp_connection_set_on_connect(&ccfg->client, on_cc_connect);

    tcp_connect(&ccfg->client);
}

void on_cc_close(tcp_client *client) {
    client_cfg *ccfg = (client_cfg*)client->data;

    ccfg->status = STATUS_NOK;

    /* start reconnect timer */
    if (ccfg->keep_ev.active)
        evt_timer_stop(client->loop_on, &ccfg->keep_ev);

    evt_timer_init(&ccfg->rcn_ev, cc_reconn, SECOND(10), 0);
    evt_set_data(&ccfg->rcn_ev, ccfg);
    evt_timer_start(client->loop_on, &ccfg->rcn_ev);
}


int main(int argc, char *argv[]) {
    set_default_logif_level(LOG_INFO);

    portcfg_map = map_new(int, client_cfg*);
    client_map  = map_new(int, client_map*);

    if (argc == 2) {
        char rpath[BUFSZ];
        if (realpath(argv[1], rpath)) {
            client_parse_cfg(rpath);
        } else {
            log_fatal("no such file");
        }
    } else {
        client_parse_cfg("config.xml");
    }

    make_daemon();

    evt_loop* loop = evt_loop_init();

    /* start client connect to server */
    iterator_t it = map_begin(portcfg_map);
    for (; !iter_equal(it, map_end(portcfg_map)); it = iter_next(it)) {
        client_cfg *ccfg = *(client_cfg**)pair_second(iter_get_pointer(it));
        tcp_client_init(&ccfg->client, &servaddr, loop, 0, NULL, 0);
        ccfg->client.data = ccfg;

        tcp_connection_set_on_close(&ccfg->client, on_cc_close);
        tcp_connection_set_on_read(&ccfg->client, on_cc_read);
        tcp_connection_set_on_connect(&ccfg->client, on_cc_connect);

        tcp_connect(&ccfg->client);
    }

    evt_loop_run(loop);
    return 0;
}