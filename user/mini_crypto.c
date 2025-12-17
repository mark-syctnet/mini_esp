#include "mini_crypto.h"
#include <sodium.h>

int mini_crypto_init(void)
{
    return sodium_init();
}

int mini_encrypt(unsigned char *out,
                 const unsigned char *in,
                 unsigned long long inlen,
                 unsigned char *key,
                 unsigned long long seq)
{
    unsigned char nonce[12] = {0};
    memcpy(nonce + 4, &seq, 8);

    return crypto_aead_chacha20poly1305_ietf_encrypt(
        out, NULL,
        in, inlen,
        NULL, 0,
        NULL,
        nonce,
        key
    );
}

int mini_decrypt(unsigned char *out,
                 const unsigned char *in,
                 unsigned long long inlen,
                 unsigned char *key,
                 unsigned long long seq)
{
    unsigned char nonce[12] = {0};
    memcpy(nonce + 4, &seq, 8);

    return crypto_aead_chacha20poly1305_ietf_decrypt(
        out, NULL,
        NULL,
        in, inlen,
        NULL, 0,
        nonce,
        key
    );
}
