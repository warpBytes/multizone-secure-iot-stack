#include "pico_device.h"
#include "pico_dev_xemaclite.h"
#include "pico_stack.h"

#define BUF_SIZE 2048
#define MDIOADDR         0x07E4
#define MDIOADDR_OP      10
#define MDIOADDR_OP_WR   0x0
#define MDIOADDR_OP_RD   0x1
#define MDIOADDR_PHYADDR 5
#define MDIOADDR_REGADDR 0
#define MDIOWR           0x07E8
#define MDIORD           0x07EC
#define MDIOCTRL         0x07F0
#define MDIOCTRL_ENABLE  0x8
#define MDIOCTRL_STATUS  0x1
#define TX_PING_OFFSET   0x0
#define TX_PING_LENGTH   0x07F4
#define TX_PING_CONTROL  0x07FC
#define TX_PONG_OFFSET   0x0800
#define TX_PONG_LENGTH   0x0FF4
#define TX_PONG_CONTROL  0x0FFC
#define RX_PING_OFFSET   0x1000
#define RX_PING_CONTROL  0x17FC
#define RX_PONG_OFFSET   0x1800
#define RX_PONG_CONTROL  0x1FFC

#define CONTROL_STATUS_BIT 0x1

uint8_t *xemaclite_base = (unsigned char*)0x60000000;

static int pico_xemaclite_send(struct pico_device *dev, void *buf, int len)
{
    uint8_t rem[4] = {0};
    IGNORE_PARAMETER(dev);
    if (len > BUF_SIZE) {
        return 0;
    }

    volatile uint32_t *txpingctrl_reg = (volatile uint32_t*)(xemaclite_base + TX_PING_CONTROL);
    volatile uint32_t *txpongctrl_reg = (volatile uint32_t*)(xemaclite_base + TX_PONG_CONTROL);
    volatile uint32_t *txpinglen_reg = (volatile uint32_t*)(xemaclite_base + TX_PING_LENGTH);
    volatile uint32_t *txponglen_reg = (volatile uint32_t*)(xemaclite_base + TX_PONG_LENGTH);

    uint32_t txping_busy = !!(*txpingctrl_reg & CONTROL_STATUS_BIT);
    uint32_t txpong_busy = !!(*txpongctrl_reg & CONTROL_STATUS_BIT);

    __sync_synchronize();

    if (txping_busy && txpong_busy) {
        return 0;
    }

    int ndwords = len/4;
    uint32_t *dword_src_buf = (uint32_t*)buf;
    uint32_t *dword_dst_buf = 0;

    if (!txping_busy) {
        dword_dst_buf = (uint32_t*)(xemaclite_base + TX_PING_OFFSET);
    } else if (!txpong_busy) {
        dword_dst_buf = (uint32_t*)(xemaclite_base + TX_PONG_OFFSET);
    } else {
        printf("Weird status\n");
        return 0;
    }

    // xilinx ethernetlite doesn't support byte enables
    // so we have to write 32-bit words
    int dword;
    for (dword = 0; dword < ndwords; dword++) {
        *dword_dst_buf++ = *dword_src_buf++;
    }

    if (len - ndwords*4 > 0) {
        // handle the remainder
        memcpy(rem, &buf[ndwords*4], len - ndwords*4);
        *dword_dst_buf = *(uint32_t*)rem;
    }

    if (!txping_busy) {
        *txpinglen_reg = len;
        __sync_synchronize();
        *txpingctrl_reg |= CONTROL_STATUS_BIT;
    } else if (!txpong_busy) {
        *txponglen_reg = len;
        __sync_synchronize();
        *txpongctrl_reg |= CONTROL_STATUS_BIT;
    }

    return len;
}

static uint16_t get_type(uint8_t *buf)
{
    uint16_t type = 0;

    type = buf[12];
    type <<= 8;
    type |= buf[13];

    return type;
}

#define FCS_SIZE 4
#define ETHERNET_HEADER_SIZE 14
#define ARP_PACKET_SIZE 28
#define MTU 1500

#define TYPE_ARP 0x0806
#define TYPE_IPV4 0x0800

static uint16_t ensure_min_length(uint16_t length)
{
    if (length < 60)
        return 60;
    else
        return length;
}

static uint16_t get_length(uint8_t *buf)
{
    uint16_t type = get_type(buf);

    if (type == TYPE_ARP) {
        return ensure_min_length(ETHERNET_HEADER_SIZE + ARP_PACKET_SIZE) + FCS_SIZE;
    } else if (type == TYPE_IPV4) {
        uint16_t ipv4_len = 0;
        ipv4_len = buf[16];
        ipv4_len <<= 8;
        ipv4_len |= buf[17];

        return ensure_min_length(ETHERNET_HEADER_SIZE + ipv4_len) + FCS_SIZE;
    } else {
        return MTU;
    }
}

static int pico_xemaclite_poll(struct pico_device *dev, int loop_score)
{
    if (loop_score <= 0) {
        return 0;
    }

    volatile uint8_t *rxping_buf = (uint8_t*)(xemaclite_base + RX_PING_OFFSET);
    volatile uint8_t *rxpong_buf = (uint8_t*)(xemaclite_base + RX_PONG_OFFSET);
    volatile uint32_t *rxpingctrl_reg = (uint32_t*)(xemaclite_base + RX_PING_CONTROL);
    volatile uint32_t *rxpongctrl_reg = (uint32_t*)(xemaclite_base + RX_PONG_CONTROL);

    if((*rxpingctrl_reg & CONTROL_STATUS_BIT) && loop_score > 0) {
        pico_stack_recv(dev, rxping_buf, get_length(rxping_buf));
        *rxpingctrl_reg &= ~CONTROL_STATUS_BIT;

        loop_score--;
    }

    if((*rxpongctrl_reg & CONTROL_STATUS_BIT) && loop_score > 0) {
        pico_stack_recv(dev, rxpong_buf, get_length(rxpong_buf));
        *rxpongctrl_reg &= ~CONTROL_STATUS_BIT;

        loop_score--;
    }

    return loop_score;
}

struct pico_device *pico_xemaclite_create(void)
{
    uint8_t mac[6] = {0x00, 0x00, 0x5E, 0x00, 0xFA, 0xCE};
    struct pico_device *xemaclite = PICO_ZALLOC(sizeof(struct pico_device));
    if (!xemaclite) {
        return NULL;
    }

    if( 0 != pico_device_init(xemaclite, "xemaclite", mac)) {
        dbg ("Xilinx EthernetLite init failed.\n");
        pico_device_destroy(xemaclite);
        return NULL;
    }

    xemaclite->send = pico_xemaclite_send;
    xemaclite->poll = pico_xemaclite_poll;
    dbg("Device %s created.\n", xemaclite->name);
    return xemaclite;
}

void pico_xemaclite_mdio_write(uint8_t phyaddr, uint8_t regaddr, uint16_t data)
{
    phyaddr &= 0x1F;
    regaddr &= 0x1F;

    volatile uint32_t *mdioaddr_reg = (uint32_t*)(xemaclite_base + MDIOADDR);
    volatile uint32_t *mdiowr_reg = (uint32_t*)(xemaclite_base + MDIOWR);
    volatile uint32_t *mdioctrl_reg = (uint32_t*)(xemaclite_base + MDIOCTRL);

    *mdioaddr_reg = (MDIOADDR_OP_WR << MDIOADDR_OP) |
                    (phyaddr << MDIOADDR_PHYADDR)   |
                    (regaddr << MDIOADDR_REGADDR);
    *mdiowr_reg = data;
    *mdioctrl_reg |= MDIOCTRL_ENABLE;
    *mdioctrl_reg |= MDIOCTRL_STATUS;

    while (*mdioctrl_reg & MDIOCTRL_STATUS);
}

uint16_t pico_xemaclite_mdio_read(uint8_t phyaddr, uint8_t regaddr)
{
    uint16_t data;

    phyaddr &= 0x1F;
    regaddr &= 0x1F;

    volatile uint32_t *mdioaddr_reg = (uint32_t*)(xemaclite_base + MDIOADDR);
    volatile uint32_t *mdiord_reg = (uint32_t*)(xemaclite_base + MDIORD);
    volatile uint32_t *mdioctrl_reg = (uint32_t*)(xemaclite_base + MDIOCTRL);

    *mdioaddr_reg = (MDIOADDR_OP_RD << MDIOADDR_OP) |
                    (phyaddr << MDIOADDR_PHYADDR)   |
                    (regaddr << MDIOADDR_REGADDR);
    *mdioctrl_reg |= MDIOCTRL_ENABLE;
    *mdioctrl_reg |= MDIOCTRL_STATUS;

    while (*mdioctrl_reg & MDIOCTRL_STATUS);

    data = *mdiord_reg & 0xFFFF;

    return data;
}
