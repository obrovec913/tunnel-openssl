#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <openssl/evp.h>

int main() {
     OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG, NULL);

    ENGINE *engine_list = ENGINE_get_first();
    while (engine_list != NULL)
    {
        printf("Доступный движок: %s\n", ENGINE_get_id(engine_list));
        engine_list = ENGINE_get_next(engine_list);
    }
    SSL_library_init();
    ENGINE_load_builtin_engines();
    ENGINE* engine = ENGINE_by_id("bee2evp");
    if (!engine) {
        fprintf(stderr, "Failed to load Bee2evp engine\n");
        return 1;
    }

   const EVP_CIPHER* cipher = ENGINE_get_cipher(engine, NID_undef);
    if (!cipher) {
        fprintf(stderr, "Failed to get cipher for Bee2evp engine\n");
        ENGINE_free(engine);
        return 1;
    }

    const char* ciphers = EVP_CIPHER_name(cipher);
    if (!ciphers) {
        fprintf(stderr, "Failed to get cipher name for Bee2evp engine\n");
        ENGINE_free(engine);
        return 1;
    }

    printf("Ciphers supported by Bee2evp engine:\n%s\n", ciphers);

    ENGINE_free(engine);
    return 0;
}