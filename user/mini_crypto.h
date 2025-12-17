#pragma once
int mini_crypto_init(void);
int mini_encrypt(unsigned char *, const unsigned char *, unsigned long long, unsigned char *, unsigned long long);
int mini_decrypt(unsigned char *, const unsigned char *, unsigned long long, unsigned char *, unsigned long long);
