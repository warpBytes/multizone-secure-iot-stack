/* Copyright(C) 2018 Hex Five Security, Inc. - All Rights Reserved */

#ifndef MZMSG_H
#define MZMSG_H

#include <stddef.h>

typedef struct {
    int zone;
} mzmsg_t;

void mzmsg_init(mzmsg_t *mzmsg, int zone);
int mzmsg_read(mzmsg_t *mzmsg, char *buf, size_t len);
int mzmsg_write(mzmsg_t *mzmsg, char *buf, size_t len);

#endif /* MZMSG_H */
