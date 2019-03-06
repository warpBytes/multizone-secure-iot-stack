#include "pico_device.h"
#include "pico_dev_xemaclite.h"
#include "pico_stack.h"

static int pico_xemaclite_send(struct pico_device *dev, void *buf, int len)
{
    uint32_t txping_busy, txpong_busy;
    volatile uint32_t *dword_src_buf, *dword_dst_buf;
    uint32_t dword, ndwords;
    struct xemaclite *xdev = (struct xemaclite*)dev;

    if (len > BUF_SIZE) {
        return 0;
    }

    txping_busy = !!(xdev->ctl->tx_ping_tsr & CONTROL_STATUS_BIT);
    txpong_busy = !!(xdev->ctl->tx_pong_tsr & CONTROL_STATUS_BIT);

    __sync_synchronize();

    if (txping_busy && txpong_busy) {
        return 0;
    }

    ndwords = (uint32_t)len/4;
    dword_src_buf = (uint32_t*)buf;
    dword_dst_buf = 0;

    if (!txping_busy) {
        dword_dst_buf = xdev->ctl->tx_ping;
    } else if (!txpong_busy) {
        dword_dst_buf = xdev->ctl->tx_pong;
    } else {
        printf("Weird status\n");
        return 0;
    }

    // xilinx ethernetlite doesn't support byte enables
    // so we have to write 32-bit words
    for (dword = 0; dword < ndwords; dword++) {
        *dword_dst_buf++ = *dword_src_buf++;
    }

    if (ndwords*4 < (uint32_t)len) {
        // handle the remainder
        uint32_t rem = 0;
        uint8_t *bbuf = (uint8_t*)buf;
        memcpy(&rem, &bbuf[ndwords*4], (uint32_t)len - ndwords*4);
        *dword_dst_buf = rem;
    }

    if (!txping_busy) {
        xdev->ctl->tx_ping_tplr = (uint32_t)len;
        __sync_synchronize();
        xdev->ctl->tx_ping_tsr |= CONTROL_STATUS_BIT;
    } else if (!txpong_busy) {
        xdev->ctl->tx_pong_tplr = (uint32_t)len;
        __sync_synchronize();
        xdev->ctl->tx_pong_tsr |= CONTROL_STATUS_BIT;
    }

    return len;
}

static uint16_t get_type(volatile uint8_t *buf)
{
    return (uint16_t)((buf[12] << 8) | buf[13]);
}

#define FCS_SIZE 4
#define ETHERNET_HEADER_SIZE 14
#define ARP_PACKET_SIZE 28
#define MTU 1500

#define TYPE_ARP 0x0806
#define TYPE_IPV4 0x0800

static uint32_t ensure_min_length(int length)
{
    if (length < 60)
        return 60;
    else
        return (uint32_t)length;
}

static uint32_t get_length(volatile void *buf)
{
    volatile uint8_t *bbuf = (volatile uint8_t*)buf;
    uint16_t type;

    type = get_type(bbuf);

    if (type == TYPE_ARP) {
        return ensure_min_length(ETHERNET_HEADER_SIZE + ARP_PACKET_SIZE) + FCS_SIZE;
    } else if (type == TYPE_IPV4) {
        uint16_t ipv4_len;
        ipv4_len = (uint16_t)((bbuf[16] << 8) | bbuf[17]);

        return ensure_min_length(ETHERNET_HEADER_SIZE + ipv4_len) + FCS_SIZE;
    } else {
        return MTU;
    }
}

static int pico_xemaclite_poll(struct pico_device *dev, int loop_score)
{
    struct xemaclite *xdev = (struct xemaclite*)dev;

    if (loop_score <= 0) {
        return 0;
    }

    if((xdev->ctl->rx_ping_rsr & CONTROL_STATUS_BIT) && loop_score > 0) {
        pico_stack_recv(dev, xdev->ctl->rx_ping, get_length(xdev->ctl->rx_ping));
        xdev->ctl->rx_ping_rsr &= ~CONTROL_STATUS_BIT;

        loop_score--;
    }

    if((xdev->ctl->rx_pong_rsr & CONTROL_STATUS_BIT) && loop_score > 0) {
        pico_stack_recv(dev, xdev->ctl->rx_pong, get_length(xdev->ctl->rx_pong));
        xdev->ctl->rx_pong_rsr &= ~CONTROL_STATUS_BIT;

        loop_score--;
    }

    return loop_score;
}

struct pico_device *pico_xemaclite_create(uint32_t address)
{
    uint8_t mac[6] = {0x00, 0x00, 0x5E, 0x00, 0xFA, 0xCE};
    struct xemaclite *xdev = PICO_ZALLOC(sizeof(struct xemaclite));
    if (!xdev) {
        return NULL;
    }

    xdev->ctl = (volatile struct xemaclite_ctl*)address;

    if( 0 != pico_device_init(&xdev->dev, "xemaclite", mac)) {
        dbg ("Xilinx EthernetLite init failed.\n");
        pico_device_destroy(&xdev->dev);
        PICO_FREE(xdev);
        return NULL;
    }

    xdev->dev.send = pico_xemaclite_send;
    xdev->dev.poll = pico_xemaclite_poll;
    dbg("Device %s created.\n", xdev->dev.name);
    return (struct pico_device*)xdev;
}

void pico_xemaclite_mdio_write(uint32_t address, uint8_t phyaddr, uint8_t regaddr, uint16_t data)
{
    volatile struct xemaclite_ctl *xdev_ctl = (struct xemaclite_ctl*)address;

    phyaddr &= 0x1F;
    regaddr &= 0x1F;

    xdev_ctl->mdioaddr = (MDIOADDR_OP_WR << MDIOADDR_OP)         |
                         ((uint32_t)phyaddr << MDIOADDR_PHYADDR) |
                         ((uint32_t)regaddr << MDIOADDR_REGADDR);
    xdev_ctl->mdiowr = data;
    xdev_ctl->mdioctrl |= MDIOCTRL_ENABLE;
    xdev_ctl->mdioctrl |= MDIOCTRL_STATUS;

    while (xdev_ctl->mdioctrl & MDIOCTRL_STATUS);
}

uint16_t pico_xemaclite_mdio_read(uint32_t address, uint8_t phyaddr, uint8_t regaddr)
{
    volatile struct xemaclite_ctl *xdev_ctl = (struct xemaclite_ctl*)address;
    uint16_t data;

    phyaddr &= 0x1F;
    regaddr &= 0x1F;

    xdev_ctl->mdioaddr = (MDIOADDR_OP_RD << MDIOADDR_OP)         |
                         ((uint32_t)phyaddr << MDIOADDR_PHYADDR) |
                         ((uint32_t)regaddr << MDIOADDR_REGADDR);
    xdev_ctl->mdioctrl |= MDIOCTRL_ENABLE;
    xdev_ctl->mdioctrl |= MDIOCTRL_STATUS;

    while (xdev_ctl->mdioctrl & MDIOCTRL_STATUS);

    data = xdev_ctl->mdiord & 0xFFFF;

    return data;
}
