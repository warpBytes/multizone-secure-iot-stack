/* Copyright(C) 2018 Hex Five Security, Inc. - All Rights Reserved */

#include <platform.h>
#include <libhexfive.h>

#include <stdio.h>

#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/ecc.h>

WC_RNG rng;
ecc_key eccKey;

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

static uint32_t rand_seed;

unsigned int my_rng_seed_gen(void)
{
    uint64_t cycles = ECALL_CSRR_MCYCLE();
    rand_seed += cycles;
    rand_seed ^= 0x67452301;
    rand_seed += 0xEFCDAB89;
    rand_seed ^= cycles << 16;
    rand_seed ^= 0x98BADCFE;
    rand_seed += 0x10325476;
    rand_seed += cycles >> 16;
    rand_seed ^= 0xC3D2E1F0;
    return rand_seed;
}

void eccSign(unsigned int inSz, unsigned int outSz)
{
    static unsigned char *in;
    static unsigned char *out;
    int msg[4];
    int i, ret;

    in = (unsigned char*)malloc(inSz);
    out = (unsigned char*)malloc(outSz);

    i = 0;
    while (i < inSz) {
        ECALL_YIELD();
        ECALL_RECV(2, msg);
        if (msg[0] > 0) {
            memcpy(in+i, &msg[1], msg[0]);
            i += msg[0];
        }
    }

    ret = wc_ecc_sign_hash(in, inSz, out, &outSz, &rng, &eccKey);
    msg[0] = 1;
    msg[1] = ret;
    msg[2] = outSz;
    msg[3] = 0;
    ECALL_SEND(2, msg);
    ECALL_YIELD();

    i = 0;
    while (i < outSz) {
        int len;
        if (outSz - i > 12)
            len = 12;
        else
            len = outSz - i;

        msg[0] = len;
        memcpy(&msg[1], out + i, len);
        ECALL_SEND(2, msg);
        ECALL_YIELD();
        i += len;
    }

    free(in);
    free(out);
}

int main(void)
{
    unsigned int idx = 0;
    int ret;

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("Could not initialize RNG!\n");
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

    while (1) {
        int msg[4];

        ECALL_RECV(2, msg);
        switch (msg[0]) {
            case 1:
                eccSign((unsigned int)msg[1], (unsigned int)msg[2]);
                break;

            default:
                break;
        }

        ECALL_RECV(1, msg);
        if (msg[0]) ECALL_SEND(1, msg);
        ECALL_RECV(4, msg);
        if (msg[0]) ECALL_SEND(4, msg);
        ECALL_YIELD();
    }
}
