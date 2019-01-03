#ifndef __JOLT_CRYPTO_LIB_H__
#define __JOLT_CRYPTO_LIB_H__


void pbkdf2_hmac_sha512(
        const uint8_t *passwd, size_t passwdlen, 
        const uint8_t *salt, size_t saltlen,
        uint8_t *buf, size_t dkLen,
        uint64_t c);

/* Same as pbkdf2_hmac_sha512 but also updates progress from 0 to 100 with
 * granularity 1/dkLen */
void pbkdf2_hmac_sha512_progress(
        const uint8_t *passwd, size_t passwdlen, 
        const uint8_t *salt, size_t saltlen,
        uint8_t *buf, size_t dkLen,
        uint64_t c, int8_t *progress);

#endif
