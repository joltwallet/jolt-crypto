#include "unity.h"

#include <string.h>
#include "joltcrypto.h"
#include "jolttypes.h"
#include "sodium.h"

TEST_CASE("pbkdf2", "[jolt-crypto]") {
    char key[100] = { 0 };
    char guess_hash_hex[129] = { 0 };
    char salt[100] = { 0 };
    uint32_t c = 0;

    uint512_t buf;

    /* Test Vector 1 */
    strcpy(key, "password");
    strcpy(salt, "salt");
    c = 1;
    pbkdf2_hmac_sha512((unsigned char *)key, strlen(key),
        (unsigned char *)salt, strlen(salt),
        buf, sizeof(buf), c);
    sodium_bin2hex(guess_hash_hex, sizeof(guess_hash_hex), buf, sizeof(buf));
    strlwr(guess_hash_hex);
    TEST_ASSERT_EQUAL_STRING(
		    "867f70cf1ade02cff3752599a3a53dc4" 
		    "af34c7a669815ae5d513554e1c8cf252"
		    "c02d470a285a0501bad999bfe943c08f"
		    "050235d7d68b1da55e63f73b60a57fce",
            guess_hash_hex);

    /* Test Vector 2 */
    strcpy(key, "password");
    strcpy(salt, "salt");
    c = 2;
    pbkdf2_hmac_sha512((unsigned char *)key, strlen(key),
        (unsigned char *)salt, strlen(salt),
        buf, sizeof(buf), c);
    sodium_bin2hex(guess_hash_hex, sizeof(guess_hash_hex), buf, sizeof(buf));
    strlwr(guess_hash_hex);
    TEST_ASSERT_EQUAL_STRING(
            "e1d9c16aa681708a45f5c7c4e215ceb6"
            "6e011a2e9f0040713f18aefdb866d53c"
            "f76cab2868a39b9f7840edce4fef5a82"
            "be67335c77a6068e04112754f27ccf4e",
            guess_hash_hex);

    /* Test Vector 3 */
    strcpy(key, "password");
    strcpy(salt, "salt");
    c = 4096;
    pbkdf2_hmac_sha512((unsigned char *)key, strlen(key),
        (unsigned char *)salt, strlen(salt),
        buf, sizeof(buf), c);
    sodium_bin2hex(guess_hash_hex, sizeof(guess_hash_hex), buf, sizeof(buf));
    strlwr(guess_hash_hex);
    TEST_ASSERT_EQUAL_STRING(
            "d197b1b33db0143e018b12f3d1d1479e"
            "6cdebdcc97c5c0f87f6902e072f457b5"
            "143f30602641b3d55cd335988cb36b84"
            "376060ecd532e039b742a239434af2d5",
            guess_hash_hex);

    /* Test Vector 4 */
    strcpy(key, "passwordPASSWORDpassword");
    strcpy(salt, "saltSALTsaltSALTsaltSALTsaltSALTsalt");
    c = 4096;
    pbkdf2_hmac_sha512((unsigned char *)key, strlen(key),
        (unsigned char *)salt, strlen(salt),
        buf, sizeof(buf), c);
    sodium_bin2hex(guess_hash_hex, sizeof(guess_hash_hex), buf, sizeof(buf));
    strlwr(guess_hash_hex);
    TEST_ASSERT_EQUAL_STRING(
            "8c0511f4c6e597c6ac6315d8f0362e22"
            "5f3c501495ba23b868c005174dc4ee71"
            "115b59f9e60cd9532fa33e0f75aefe30"
            "225c583a186cd82bd4daea9724a3d3b8",
            guess_hash_hex);
}
