#include "sodium.h"
#include "sodium/private/common.h"
#include "esp_err.h"

#include "jolttypes.h"
#include "joltcrypto.h"

void pbkdf2_hmac_sha512(const uint8_t *passwd, size_t passwdlen, 
        const uint8_t *salt, size_t saltlen,
        uint8_t *buf, size_t dkLen, uint64_t c){
    /*
     * c - number of iterations
     * buf - stores the derived key 
     * dkLen - derived key length in bits
     *
     * Based on the pbkdf2 sha256 code in libsodium
     */
    CONFIDENTIAL crypto_auth_hmacsha512_state PShctx;
    crypto_auth_hmacsha512_state hctx;
    size_t                       i;
    uint8_t                      ivec[4];
    CONFIDENTIAL uint8_t         U[crypto_auth_hmacsha512_BYTES];
    CONFIDENTIAL uint8_t         T[crypto_auth_hmacsha512_BYTES];
    uint64_t                     j;
    int                          k;
    size_t                       clen;

    crypto_auth_hmacsha512_init(&PShctx, passwd, passwdlen);
    crypto_auth_hmacsha512_update(&PShctx, salt, saltlen);

    for (i = 0; i * crypto_auth_hmacsha512_BYTES < dkLen; i++) {
        STORE32_BE(ivec, (uint32_t)(i + 1));
        memcpy(&hctx, &PShctx, sizeof(crypto_auth_hmacsha512_state));
        crypto_auth_hmacsha512_update(&hctx, ivec, sizeof(ivec));
        crypto_auth_hmacsha512_final(&hctx, U);

        memcpy(T, U, sizeof(T));
        /* LCOV_EXCL_START */
        for (j = 2; j <= c; j++) {
            crypto_auth_hmacsha512_init(&hctx, passwd, passwdlen);
            crypto_auth_hmacsha512_update(&hctx, U, sizeof(U));
            crypto_auth_hmacsha512_final(&hctx, U);

            for (k = 0; k < sizeof(U); k++) {
                T[k] ^= U[k];
            }
        }
        /* LCOV_EXCL_STOP */

        clen = dkLen - i * 64;
        if (clen > crypto_auth_hmacsha512_BYTES) {
            clen = crypto_auth_hmacsha512_BYTES;
        }
        memcpy(&buf[i * crypto_auth_hmacsha512_BYTES], T, clen);
    }
    sodium_memzero((void *) &PShctx, sizeof PShctx);
    sodium_memzero(U, sizeof(U));
    sodium_memzero(T, sizeof(T));
}

