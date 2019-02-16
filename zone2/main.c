/*
 * Copyright(C) 2018 Hex Five Security, Inc. - All rights reserved.
 */

#include <limits.h>

#include <platform.h>
#include <libhexfive.h>

#define RV32

#include <pico_stack.h>
#include <pico_ipv4.h>
#include <pico_icmp4.h>
#include <pico_socket.h>
#include <pico_dev_xemaclite.h>

#define NUM_PING 10

#define ACK         0
#define IND         1
#define CTL         2
#define DAT         3
#define CTL_ACK     (1 << 0)
#define CTL_DAT     (1 << 1)
#define CTL_RST     (1 << 2)
#define CTL_PSH     (1 << 3)

#define MAX_QUEUE_LEN 64

struct queue {
    uint8_t wp;
    uint8_t rp;
    uint8_t flush;
    char data[MAX_QUEUE_LEN];
};

void qinit(struct queue *q)
{
    q->rp = 0;
    q->wp = 0;
    q->flush = 0;
}

uint32_t qtaken(struct queue *q)
{
    if (q->wp < q->rp) {
        return q->wp + UCHAR_MAX + 1 - q->rp;
    } else {
        return q->wp - q->rp;
    }
}

uint32_t qfree(struct queue *q)
{
    return MAX_QUEUE_LEN - qtaken(q);
}

uint8_t qfull(struct queue *q)
{
    return qtaken(q) == MAX_QUEUE_LEN;
}

uint8_t qempty(struct queue *q)
{
    return qtaken(q) == 0;
}

void qinsert(struct queue *q, char e)
{
    q->data[q->wp % MAX_QUEUE_LEN] = e;
    q->wp++;
}

char *qfront(struct queue *q)
{
    return &q->data[q->rp % MAX_QUEUE_LEN];
}

uint32_t qcontlen(struct queue *q)
{
    uint32_t rdp = q->rp % MAX_QUEUE_LEN;
    uint32_t wdp = q->wp % MAX_QUEUE_LEN;

    if (wdp <= rdp && q->wp != q->rp) {
        return MAX_QUEUE_LEN - rdp;
    } else {
        return wdp - rdp;
    }
}

static int finished = 0;

void *pico_zalloc(size_t size)
{
    void *ptr = malloc(size);
    if(ptr)
        memset(ptr, 0u, size);

    return ptr;
}

void pico_free(void *ptr)
{
    free(ptr);
}

pico_time PICO_TIME_MS(void)
{
    return (pico_time)(ECALL_CSRR_MCYCLE() * 1000 / CPU_FREQ);
}

pico_time PICO_TIME(void)
{
    return (pico_time)(ECALL_CSRR_MCYCLE() / CPU_FREQ);
}

void PICO_IDLE(void)
{
    ECALL_YIELD();
}

/* gets called when the ping receives a reply, or encounters a problem */
void cb_ping(struct pico_icmp4_stats *s)
{
    char host[30];
    pico_ipv4_to_string(host, s->dst.addr);
    if (s->err == 0) {
        /* if all is well, print some pretty info */
        printf("%lu bytes from %s: icmp_req=%lu ttl=%lu time=%lu ms\n", s->size,
                host, s->seq, s->ttl, (long unsigned int)s->time);
    } else {
        /* if something went wrong, print it and signal we want to stop */
        printf("PING %lu to %s: Error %d\n", s->seq, host, s->err);
    }
}

#define IAC "\xff"

#define WILL "\xfb"
#define DONT "\xfe"

#define ECHO "\x01"
#define SUPRESS_GO_AHEAD "\x03"
#define LINEMODE "\x22"

struct pico_socket *sock_client = NULL;

void cb_telnet(uint16_t ev, struct pico_socket *s)
{
    if (ev & PICO_SOCK_EV_CONN) {
        struct pico_ip4 ipaddr;
        uint16_t port;
        uint32_t yes = 1;
        const char mode[] = IAC DONT LINEMODE
                            IAC WILL SUPRESS_GO_AHEAD
                            IAC WILL ECHO;

        sock_client = pico_socket_accept(s, &ipaddr.addr, &port);
        pico_socket_setoption(sock_client, PICO_TCP_NODELAY, &yes);
        pico_socket_write(sock_client, mode, sizeof(mode));
    }

    if (ev & PICO_SOCK_EV_CLOSE) {
        sock_client = NULL;

        if (ev & PICO_SOCK_EV_RD) {
            pico_socket_shutdown(s, PICO_SHUT_WR);
        }
    }
}

void mzmsg_proc(struct queue *txq, struct queue *rxq)
{
    static int ack_pending = 0;
    static int ack_index = 0;
    static int flush = 0;
    static int resend = 0;
    static int msg[4] = {0,0,0,0};
    static int msg_out[4] = {-1,0,0,0};
    int tmp_msg[4] = {0,0,0,0};

    ECALL_RECV(1, (void*)tmp_msg);

    if (!(tmp_msg[0] == 0 && tmp_msg[1] == 0 && tmp_msg[2] == 0 && tmp_msg[3] == 0)) {
        memcpy(msg, tmp_msg, 4*sizeof(int));
    }

    if ((msg[CTL] & CTL_RST) != 0) {
        ack_pending = 0;
        ack_index = 0;
        memcpy(msg_out, (int[]){-1,0,0,0}, 4*sizeof(int));
        ECALL_SEND(1, (int[]){0,0,CTL_RST,0});
    }

    if ((msg[CTL] & CTL_DAT) != 0) {
        if (msg[IND] == (msg_out[ACK] + 1)) {
            if (qfree(txq) >= MZMSG_CHARS) {
                int ack = 0;
                char *data = (char*)&msg[DAT];

                while (*data != 0 && ack < MZMSG_CHARS) {
                    qinsert(txq, *data);
                    ack++;
                    data++;
                }

                msg_out[CTL] |= CTL_ACK;
                msg_out[ACK] = msg[IND];
                flush = 1;

                if ((msg[CTL] & CTL_PSH) != 0) {
                    txq->flush = 1;
                }
            }
        }
    }

    if (!ack_pending && rxq->flush) {
        msg_out[CTL] |= CTL_DAT;
        msg_out[IND] = ack_index;
        memcpy(&msg_out[DAT], qfront(rxq), 1);
        rxq->rp += 1;
        rxq->flush = 0;
        flush = 1;
        ack_pending = 1;
    }

    if (((msg[CTL] & CTL_ACK) != 0) & ack_pending) {
        if (msg[ACK] >= ack_index) {
            ack_index = msg[ACK] + 1;
            ack_pending = 0;
        }
    }

    if (flush != 0) {
        flush = 0;
        ECALL_SEND(1, (void*)msg_out);
    }
}

void telnet_client(struct pico_socket *client, struct queue *txq, struct queue *rxq)
{
    char buf[32];
    int bytes = 0;

    if (qfree(rxq) < MZMSG_CHARS || rxq->flush) {
        bytes = pico_socket_write(sock_client, qfront(rxq), qcontlen(rxq));
        rxq->rp += bytes;
        if (qcontlen(rxq) > 0) {
            bytes = pico_socket_write(sock_client, qfront(rxq), qcontlen(rxq));
            rxq->rp += bytes;
        }
        rxq->flush = 0;
    }

    if (qfree(txq) > 0) {
        bytes = pico_socket_read(sock_client, buf, 1);
        if (bytes > 0) {
            if (buf[0] == '\xff') { // swallow IAC sequences
                pico_socket_read(sock_client, buf, sizeof(buf));
            } else if (buf[0] != 0) {
                qinsert(txq, buf[0]);
                txq->flush = 1;
            }
        }
    }
}

#define PHY_ADDRESS 0x01
#define BMSR_REG 0x01
#define BMSR_LINK_STATUS 0x4

#define DO_QUOTE(X)  #X
#define QUOTE(X)     DO_QUOTE(X)

int main(int argc, char *argv[]){
    int id;
    uint16_t port = short_be(23);
    uint32_t yes = 1;
    struct pico_ip4 ipaddr, netmask;
    struct pico_socket* socket;
    struct pico_device* dev;
    struct queue mzmsg_to1, mzmsg_from1;
    uint16_t bmsr;

    do {
        ECALL_YIELD();
        bmsr = pico_xemaclite_mdio_read(PHY_ADDRESS, BMSR_REG);
    } while ((bmsr & BMSR_LINK_STATUS) == 0);

    qinit(&mzmsg_to1);
    qinit(&mzmsg_from1);

    /* initialise the stack. Super important if you don't want ugly stuff like
     * segfaults and such! */
    pico_stack_init();

    printf("pico stack initialized\n");

    dev = pico_xemaclite_create();
    if (!dev) {
        printf("Could not initialize device\n");
        return -1;
    }

    /* assign the IP address to the tap interface */
    #ifndef IPADDR
        #error "IPADDR not defined! Please provide it via `make IPADDR=....`"
    #endif
    pico_string_to_ipv4(QUOTE(IPADDR), &ipaddr.addr);
    #ifndef NETMASK
        #warning "NETMASK not defined, assuming 255.255.255.0. You can provide one via `make NETMASK=...`"
        #define NETMASK "255.255.255.0"
    #endif
    pico_string_to_ipv4(QUOTE(NETMASK), &netmask.addr);
    pico_ipv4_link_add(dev, ipaddr, netmask);

    printf("Listening on port %d\n", short_be(port));
    socket = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, cb_telnet);
    if (!socket) {
        printf("Could not open socket!\n");
        return -1;
    }

    pico_socket_setoption(socket, PICO_TCP_NODELAY, &yes);

    if (pico_socket_bind(socket, &ipaddr, &port) != 0) {
        printf("Could not bind!\n");
        return -1;
    }

    if (pico_socket_listen(socket, 1) != 0) {
        printf("Could not start listening!\n");
        return -1;
    }

    /* keep running stack ticks to have picoTCP do its network magic. Note that
     * you can do other stuff here as well, or sleep a little. This will impact
     * your network performance, but everything should keep working (provided
     * you don't go overboard with the delays). */
    while (finished != 1)
    {
        int msg[4] = {0,0,0,0};

        mzmsg_proc(&mzmsg_from1, &mzmsg_to1);

        if (sock_client) {
            telnet_client(sock_client, &mzmsg_to1, &mzmsg_from1);
        }
        pico_stack_tick();

        ECALL_RECV(4, msg);
        if (msg[0]) ECALL_SEND(4, msg);
        ECALL_YIELD();
    }

    printf("finished !\n");
    return 0;
}
