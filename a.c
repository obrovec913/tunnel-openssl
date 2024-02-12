#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/engine.h>

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

    if (!ENGINE_set_default(engine, ENGINE_METHOD_ALL))
    {
        handleErrors("Failed to set Bee2evp engine as default");
    }

    SSL_CTX *ssl_ctx = SSL_CTX_new(SSLv23_client_method()); // Создание SSL контекста
    if (!ssl_ctx)
    {
        handleErrors("Failed to create SSL context");
    }
    // Установка списка шифров
    //const char *ciphers = "belt-ecb128:belt-ecb192:belt-ecb256:belt-cbc128:belt-cbc192:belt-cbc256:belt-cfb128:belt-cfb192:belt-cfb256:belt-ctr128:belt-ctr192:belt-ctr256:belt-dwp128:belt-dwp192:belt-dwp256:belt-kwp128:belt-kwp192:belt-kwp256:bash256:bash384:bash512:belt-hash:bign-with-hspec:bign-with-hbelt:bign-with-bash256:bign-with-bash384:bign-with-bash512:bign-keytransport:bign-curve256v1:bign-curve384v1:bign-curve512v1:bign-primefield:bign-pubkey:belt-mac128:belt-mac192:belt-mac256:belt-hmac";
    const EVP_CIPHER *cipher = EVP_get_cipherbyname("belt-cbc128");
    if (!cipher)
        handleErrors();

    if (!SSL_CTX_set_cipher_list(ssl_ctx, cipher))
    {
        handleErrors("Failed to set cipher list");
    }
    return 0;


}