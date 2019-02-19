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

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/logging.h>

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
WOLFSSL_CTX *ctx = NULL;
WOLFSSL *ssl = NULL;

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
        if (qempty(rxq))
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
        if (qempty(rxq))
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

static const char cert_der[] = {
  0x30, 0x82, 0x02, 0x63, 0x30, 0x82, 0x02, 0x0a, 0xa0, 0x03, 0x02, 0x01,
  0x02, 0x02, 0x14, 0x45, 0xd1, 0x4e, 0x37, 0xbd, 0x08, 0xdd, 0x5e, 0x17,
  0xb0, 0xec, 0xd0, 0xce, 0x68, 0xe5, 0xad, 0x1c, 0x64, 0x4b, 0x4b, 0x30,
  0x09, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01, 0x30, 0x81,
  0x87, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
  0x55, 0x4b, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c,
  0x06, 0x4c, 0x6f, 0x6e, 0x64, 0x6f, 0x6e, 0x31, 0x0f, 0x30, 0x0d, 0x06,
  0x03, 0x55, 0x04, 0x07, 0x0c, 0x06, 0x4c, 0x6f, 0x6e, 0x64, 0x6f, 0x6e,
  0x31, 0x1a, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x11, 0x77,
  0x61, 0x72, 0x70, 0x42, 0x79, 0x74, 0x65, 0x73, 0x20, 0x4c, 0x69, 0x6d,
  0x69, 0x74, 0x65, 0x64, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04,
  0x03, 0x0c, 0x0d, 0x77, 0x61, 0x72, 0x70, 0x62, 0x79, 0x74, 0x65, 0x73,
  0x2e, 0x63, 0x6f, 0x6d, 0x31, 0x22, 0x30, 0x20, 0x06, 0x09, 0x2a, 0x86,
  0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x13, 0x62, 0x6f, 0x72,
  0x61, 0x6e, 0x40, 0x77, 0x61, 0x72, 0x70, 0x62, 0x79, 0x74, 0x65, 0x73,
  0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x39, 0x30, 0x32,
  0x31, 0x39, 0x30, 0x30, 0x32, 0x37, 0x30, 0x39, 0x5a, 0x17, 0x0d, 0x32,
  0x30, 0x30, 0x32, 0x31, 0x39, 0x30, 0x30, 0x32, 0x37, 0x30, 0x39, 0x5a,
  0x30, 0x81, 0x87, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
  0x13, 0x02, 0x55, 0x4b, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04,
  0x08, 0x0c, 0x06, 0x4c, 0x6f, 0x6e, 0x64, 0x6f, 0x6e, 0x31, 0x0f, 0x30,
  0x0d, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x06, 0x4c, 0x6f, 0x6e, 0x64,
  0x6f, 0x6e, 0x31, 0x1a, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
  0x11, 0x77, 0x61, 0x72, 0x70, 0x42, 0x79, 0x74, 0x65, 0x73, 0x20, 0x4c,
  0x69, 0x6d, 0x69, 0x74, 0x65, 0x64, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03,
  0x55, 0x04, 0x03, 0x0c, 0x0d, 0x77, 0x61, 0x72, 0x70, 0x62, 0x79, 0x74,
  0x65, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x31, 0x22, 0x30, 0x20, 0x06, 0x09,
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x13, 0x62,
  0x6f, 0x72, 0x61, 0x6e, 0x40, 0x77, 0x61, 0x72, 0x70, 0x62, 0x79, 0x74,
  0x65, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07,
  0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
  0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xf7, 0xde, 0x4e,
  0x14, 0x5f, 0xbd, 0x6f, 0x4f, 0xea, 0xb4, 0x9b, 0x56, 0x44, 0x05, 0x1b,
  0x9a, 0x3f, 0x0a, 0x5f, 0x02, 0x2a, 0x32, 0x5f, 0x40, 0xea, 0xcd, 0xee,
  0x05, 0x90, 0x2e, 0xc3, 0x1a, 0xa0, 0xbb, 0x56, 0xd7, 0xcf, 0xd9, 0x8d,
  0x6e, 0x8c, 0xf5, 0xe0, 0x0c, 0xff, 0x06, 0xdd, 0xf5, 0x02, 0x62, 0xd6,
  0xed, 0x99, 0xd1, 0x4c, 0xad, 0xfd, 0xd8, 0x47, 0x35, 0x49, 0x86, 0x45,
  0x06, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e,
  0x04, 0x16, 0x04, 0x14, 0x1c, 0x31, 0x4c, 0x84, 0xf0, 0x8c, 0x85, 0x2a,
  0x12, 0xd5, 0x2e, 0xbe, 0x58, 0x9b, 0x93, 0x25, 0xe6, 0x18, 0x56, 0xf8,
  0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80,
  0x14, 0x1c, 0x31, 0x4c, 0x84, 0xf0, 0x8c, 0x85, 0x2a, 0x12, 0xd5, 0x2e,
  0xbe, 0x58, 0x9b, 0x93, 0x25, 0xe6, 0x18, 0x56, 0xf8, 0x30, 0x0f, 0x06,
  0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01,
  0x01, 0xff, 0x30, 0x09, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04,
  0x01, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0xfa, 0x00, 0xda,
  0xe7, 0xa1, 0xbb, 0xef, 0x60, 0x8b, 0x5d, 0xd5, 0x76, 0xb0, 0xa5, 0x24,
  0x7e, 0x62, 0x47, 0x55, 0x1a, 0x24, 0xf1, 0xdd, 0x62, 0xf9, 0x80, 0x2b,
  0x6a, 0x57, 0x92, 0x9d, 0x7d, 0x02, 0x20, 0x17, 0xeb, 0x88, 0xb1, 0x61,
  0x74, 0x01, 0x30, 0x85, 0x5c, 0xe7, 0x1b, 0x9d, 0x41, 0xab, 0x16, 0x84,
  0xdb, 0x00, 0x99, 0x06, 0x30, 0xfb, 0x95, 0xd3, 0xdb, 0xb6, 0x79, 0x85,
  0xdf, 0xb0, 0xac
};

static const char key_der[] = {
  0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x09, 0x5f, 0xdd, 0x40, 0x49,
  0x93, 0x86, 0x7d, 0x4c, 0x97, 0x8e, 0x49, 0x84, 0xdb, 0x00, 0xfe, 0x5f,
  0xb4, 0x71, 0x1d, 0xd6, 0x1c, 0x27, 0x6e, 0xa2, 0x89, 0x03, 0xc3, 0xf0,
  0x8b, 0x50, 0xe0, 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
  0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0xf7, 0xde, 0x4e,
  0x14, 0x5f, 0xbd, 0x6f, 0x4f, 0xea, 0xb4, 0x9b, 0x56, 0x44, 0x05, 0x1b,
  0x9a, 0x3f, 0x0a, 0x5f, 0x02, 0x2a, 0x32, 0x5f, 0x40, 0xea, 0xcd, 0xee,
  0x05, 0x90, 0x2e, 0xc3, 0x1a, 0xa0, 0xbb, 0x56, 0xd7, 0xcf, 0xd9, 0x8d,
  0x6e, 0x8c, 0xf5, 0xe0, 0x0c, 0xff, 0x06, 0xdd, 0xf5, 0x02, 0x62, 0xd6,
  0xed, 0x99, 0xd1, 0x4c, 0xad, 0xfd, 0xd8, 0x47, 0x35, 0x49, 0x86, 0x45,
  0x06
};

void cb_tls(uint16_t ev, struct pico_socket *s)
{
    struct pico_socket *sock_tls;

    if (ev & PICO_SOCK_EV_CONN) {
        struct pico_ip4 ipaddr;
        uint16_t port;

        sock_tls = pico_socket_accept(s, &ipaddr.addr, &port);
        ssl = wolfSSL_new(ctx);
        wolfSSL_SetIOReadCtx(ssl, sock_tls);
        wolfSSL_SetIOWriteCtx(ssl, sock_tls);
    }

    if (ev & PICO_SOCK_EV_CLOSE) {
        wolfSSL_free(ssl);
        ssl = NULL;

        if (ev & PICO_SOCK_EV_RD) {
            pico_socket_shutdown(s, PICO_SHUT_WR);
        }
    }
}

void tls_client(WOLFSSL *ssl, struct queue *txq, struct queue *rxq)
{
    int ret, error;
    char buf[32];
    int bytes;

    ret = wolfSSL_accept(ssl);
    error = wolfSSL_get_error(ssl, 0);

    if (ret != WOLFSSL_SUCCESS) {
        ret = wolfSSL_accept(ssl);
    } else {
        if (qfree(rxq) < MZMSG_CHARS || rxq->flush) {
            bytes = wolfSSL_write(ssl, qfront(rxq), qcontlen(rxq));
            rxq->rp += bytes;
            if (qcontlen(rxq) > 0) {
                bytes = wolfSSL_write(ssl, qfront(rxq), qcontlen(rxq));
                rxq->rp += bytes;
            }
            if (qempty(rxq))
                rxq->flush = 0;
        }

        if (qfree(txq) > 0) {
            bytes = wolfSSL_read(ssl, buf, 1);
            if (bytes > 0) {
                if (buf[0] == '\xff') { // swallow IAC sequences
                    wolfSSL_read(ssl, buf, sizeof(buf));
                } else if (buf[0] != 0) {
                    qinsert(txq, buf[0]);
                    txq->flush = 1;
                }
            }
        }
    }
}

unsigned int my_rng_seed_gen(void)
{
    return pico_rand();
}

#include <wolfssl/wolfcrypt/ecc.h>

WC_RNG rng;
ecc_key eccKey;

static int eccSign(WOLFSSL* ssl,
       const unsigned char* in, unsigned int inSz,
       unsigned char* out, unsigned int* outSz,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx)
{
    return wc_ecc_sign_hash(in, inSz, out, outSz, &rng, &eccKey);
}

static int wolfRecv(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    int ret;
    struct pico_socket *sock_tls = (struct pico_socket*)ctx;

    ret = pico_socket_read(sock_tls, buf, sz);

    if (ret == 0) {
        return WOLFSSL_CBIO_ERR_WANT_READ;
    } else {
        return ret;
    }
}

static int wolfSend(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    int ret;
    struct pico_socket *sock_tls = (struct pico_socket*)ctx;

    ret = pico_socket_write(sock_tls, buf, sz);

    if (ret == 0) {
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    } else {
        return ret;
    }
}

int main(int argc, char *argv[]){
    unsigned int idx = 0;
    uint16_t telnet_port = short_be(23);
    uint16_t tls_port = short_be(443);
    uint32_t yes = 1;
    struct pico_ip4 ipaddr, netmask;
    struct pico_socket* socket;
    struct pico_device* dev;
    struct queue mzmsg_to1, mzmsg_from1;
    uint16_t bmsr;
    int ret;

    do {
        ECALL_YIELD();
        bmsr = pico_xemaclite_mdio_read(PHY_ADDRESS, BMSR_REG);
    } while ((bmsr & BMSR_LINK_STATUS) == 0);

    qinit(&mzmsg_to1);
    qinit(&mzmsg_from1);

    /* initialise the stack. Super important if you don't want ugly stuff like
     * segfaults and such! */
    pico_stack_init();
    wolfSSL_Init();

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

    printf("Listening on port %d\n", short_be(telnet_port));
    socket = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, cb_telnet);
    if (!socket) {
        printf("Could not open socket!\n");
        return -1;
    }

    pico_socket_setoption(socket, PICO_TCP_NODELAY, &yes);

    if (pico_socket_bind(socket, &ipaddr, &telnet_port) != 0) {
        printf("Could not bind!\n");
        return -1;
    }

    if (pico_socket_listen(socket, 1) != 0) {
        printf("Could not start listening!\n");
        return -1;
    }

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (!ctx) {
        printf("Could not initialize wolfSSL context!\n");
        return -1;
    }
    wolfSSL_CTX_SetIORecv(ctx, wolfRecv);
    wolfSSL_CTX_SetIOSend(ctx, wolfSend);

    ret = wolfSSL_CTX_use_certificate_buffer(ctx, cert_der, sizeof(cert_der), SSL_FILETYPE_ASN1);
    if (ret != SSL_SUCCESS) {
        printf("Could not load certificate!\n");
        return -1;
    }

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("Could not init rng!\n");
        return -1;
    }

    ret = wc_ecc_init(&eccKey);
    if (ret != 0) {
        printf("Could not init ECC key!\n");
        return -1;
    }

    ret = wc_EccPrivateKeyDecode(key_der, &idx, &eccKey, sizeof(key_der));
    if (ret != 0) {
        printf("Could not decode private ECC key!\n");
        return -1;
    }

    wolfSSL_CTX_SetEccSignCb(ctx, eccSign);

    socket = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, cb_tls);
    if (!socket) {
        printf("Could not open socket!\n");
        return -1;
    }

    if (pico_socket_bind(socket, &ipaddr, &tls_port) != 0) {
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

        if (ssl) {
            tls_client(ssl, &mzmsg_to1, &mzmsg_from1);
        }

        pico_stack_tick();

        ECALL_RECV(4, msg);
        if (msg[0]) ECALL_SEND(4, msg);
        ECALL_YIELD();
    }

    printf("finished !\n");
    return 0;
}
