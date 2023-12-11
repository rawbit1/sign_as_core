#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <secp256k1.h>
#include <assert.h>

#if defined(__linux__)
    #include <endian.h>
#elif defined(__APPLE__)
    #include <libkern/OSByteOrder.h>
    #define htole32(x) OSSwapHostToLittleInt32(x)
#elif defined(_WIN32)
    #include <winsock2.h>
    #define htole32(x) (x)
#else
    static uint32_t htole32(uint32_t x) {
        uint8_t data[4] = {
            (x >> 0) & 0xFF,
            (x >> 8) & 0xFF,
            (x >> 16) & 0xFF,
            (x >> 24) & 0xFF
        };
        return *((uint32_t*)data);
    }
#endif

void static inline WriteLE32(unsigned char* ptr, uint32_t x) {
    uint32_t v = htole32(x);
    memcpy(ptr, &v, 4);
}

void hex_to_bytes(const char *hex_str, unsigned char *byte_array, int byte_array_length) {
    for (int i = 0; i < byte_array_length; i++) {
        sscanf(hex_str + 2 * i, "%2hhx", &byte_array[i]);
    }
}

int is_low_r(const secp256k1_ecdsa_signature *sig, secp256k1_context *ctx) {
    unsigned char compact_sig[64];
    secp256k1_ecdsa_signature_serialize_compact(ctx, compact_sig, sig);
    return compact_sig[0] < 0x80;
}

void print_signature(const secp256k1_ecdsa_signature *sig, secp256k1_context *ctx, const char* label) {
    unsigned char der_signature[72];
    size_t der_sig_len = sizeof(der_signature);
    secp256k1_ecdsa_signature_serialize_der(ctx, der_signature, &der_sig_len, sig);

    printf("%s Signature: ", label);
    for (size_t i = 0; i < der_sig_len; i++) {
        printf("%02x", der_signature[i]);
    }
    printf("\n");
}

// Function to find the first low R signature
void find_low_r_signature(const char *priv_key_hex, const char *msg_hash_hex) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    unsigned char priv_key[32];
    unsigned char msg_hash[32];
    hex_to_bytes(priv_key_hex, priv_key, sizeof(priv_key));
    hex_to_bytes(msg_hash_hex, msg_hash, sizeof(msg_hash));

    secp256k1_ecdsa_signature signature;
    unsigned char extra_entropy[32] = {0};
    uint32_t counter = 0;
    int ret;

    int grind = 1;
    do {
        WriteLE32(extra_entropy, ++counter);
        ret = secp256k1_ecdsa_sign(ctx, &signature, msg_hash, priv_key, secp256k1_nonce_function_rfc6979, grind ? extra_entropy : NULL);
        assert(ret);

        if (!is_low_r(&signature, ctx)) {
            print_signature(&signature, ctx, "High R");
            counter++;
        } else {
            print_signature(&signature, ctx, "Low R");
            break;
        }
    } while (grind);

    secp256k1_context_destroy(ctx);
}

// Wrapper function
void find_low_r_signature_wrapper(const char *priv_key_hex, const char *msg_hash_hex) {
    find_low_r_signature(priv_key_hex, msg_hash_hex);
}


// gcc -shared -o libsign.so -fPIC sign.c -lsecp256k1