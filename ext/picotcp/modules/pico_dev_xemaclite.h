#ifndef INCLUDE_PICO_XEMACLITE
#define INCLUDE_PICO_XEMACLITE
#include "pico_config.h"
#include "pico_device.h"

void pico_xemaclite_destroy(struct pico_device *xethlite);
struct pico_device *pico_xemaclite_create(void);

void pico_xemaclite_mdio_write(uint8_t phyaddr, uint8_t regaddr, uint16_t data);
uint16_t pico_xemaclite_mdio_read(uint8_t phyaddr, uint8_t regaddr);

#endif
