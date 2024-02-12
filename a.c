#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <openssl/evp.h>

void handleErrors(const char *message)
{
    perror(message);
    exit(EXIT_FAILURE);
}

void printCipherList(SSL_CTX *ssl_ctx)
{
    const char *ciphers = SSL_get_cipher_list(ssl_ctx, 0);
    printf("Supported ciphers:\n");
    while (ciphers != NULL)
    {
        printf("%s\n", ciphers);
        ciphers = SSL_get_cipher_list(ssl_ctx, 1);
    }
}

int main()
{
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG, NULL);

    ENGINE *engine_list = ENGINE_get_first();
    while (engine_list != NULL)
    {
        printf("Available Engine: %s\n", ENGINE_get_id(engine_list));
        engine_list = ENGINE_get_next(engine_list);
    }
    ENGINE_load_builtin_engines();            // Загрузка встроенных движков OpenSSL
    ENGINE *engine = ENGINE_by_id("bee2evp"); // Получение указателя на движок Bee2evp
    if (!engine)
    {
        handleErrors("Failed to load Bee2evp engine");
    }
    if (!ENGINE_init(engine))
    {
        handleErrors("Failed to initialize Bee2evp engine");
    }

    printf("Available cipher names:\n");
    for (int i = 0; i < EVP_CIPHER_meth_nids(); ++i) {
        const char *name = OBJ_nid2sn(EVP_CIPHER_meth_nid(i));
        if (name != NULL) {
            printf("%s\n", name);
        }
    }

    return 0;
}