#ifndef INCLUDE_PICO_XEMACLITE
#define INCLUDE_PICO_XEMACLITE
#include "pico_config.h"
#include "pico_device.h"

#define BUF_SIZE 2048

#define CONTROL_STATUS_BIT 0x1UL

#define MDIOADDR_OP      10UL
#define MDIOADDR_OP_WR   0x0UL
#define MDIOADDR_OP_RD   0x1UL
#define MDIOCTRL_ENABLE  0x8UL
#define MDIOCTRL_STATUS  0x1UL

#define MDIOADDR_PHYADDR 5UL
#define MDIOADDR_REGADDR 0UL

struct xemaclite_ctl {
    uint32_t tx_ping[505]; /* 0x0000 */
    uint32_t mdioaddr;     /* 0x07E4 */
    uint32_t mdiowr;       /* 0x07E8 */
    uint32_t mdiord;       /* 0x07EC */
    uint32_t mdioctrl;     /* 0x07F0 */
    uint32_t tx_ping_tplr; /* 0x07F4 */
    uint32_t tx_isr;       /* 0x07F8 */
    uint32_t tx_ping_tsr;  /* 0x07FC */
    uint32_t tx_pong[509]; /* 0x0800 */
    uint32_t tx_pong_tplr; /* 0x0FF4 */
    uint32_t reserved;     /* 0x0FF8 */
    uint32_t tx_pong_tsr;  /* 0x0FFC */
    uint32_t rx_ping[511]; /* 0x1000 */
    uint32_t rx_ping_rsr;  /* 0x17FC */
    uint32_t rx_pong[511]; /* 0x1800 */
    uint32_t rx_pong_rsr;  /* 0x1FFC */
};

struct xemaclite {
    struct pico_device dev;
    volatile struct xemaclite_ctl *ctl;
};

void pico_xemaclite_destroy(struct pico_device *xethlite);
struct pico_device *pico_xemaclite_create(uint32_t address);

void pico_xemaclite_mdio_write(uint32_t address, uint8_t phyaddr, uint8_t regaddr, uint16_t data);
uint16_t pico_xemaclite_mdio_read(uint32_t address, uint8_t phyaddr, uint8_t regaddr);

#endif
