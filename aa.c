#include <openssl/evp.h>
#include <stdio.h>
#include <openssl/engine.h>
#include <openssl/ssl.h>

// Функция инициализации вашего собственного движка
int init_my_engine()
{
    // Загрузка собственного движка
    ENGINE *my_engine = ENGINE_by_id("bee2evp");
    if (!my_engine)
    {
        fprintf(stderr, "Failed to load your engine.\n");
        return 0;
    }

    // Инициализация собственного движка
    if (!ENGINE_init(my_engine))
    {
        fprintf(stderr, "Failed to initialize your engine.\n");
        ENGINE_free(my_engine);
        return 0;
    }

    // Зарегистрировать собственный движок
    if (!ENGINE_set_default(my_engine, ENGINE_METHOD_ALL))
    {
        fprintf(stderr, "Failed to register your engine.\n");
        ENGINE_free(my_engine);
        return 0;
    }
     // Зарегистрировать алгоритмы вашего движка
    ENGINE_register_ciphers(my_engine);

    return 1;
}

int main()
{
    // Инициализировать OpenSSL
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG, NULL);
    SSL_library_init();
    SSL_load_error_strings();
    ENGINE_load_builtin_engines();

    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();

    // Инициализация вашего собственного движка
    if (!init_my_engine())
    {
        fprintf(stderr, "Failed to initialize your engine.\n");
        return 1;
    }
    const EVP_CIPHER *cipher_belt_dwp128 = EVP_get_cipherbyname("belt-dwp128");
    if (cipher_belt_dwp128) {
        printf("Algorithm belt-dwp128 is available.\n");
    } else {
        printf("Algorithm belt-dwp128 is not available.\n");
    }

    // Проверка наличия алгоритма belt-dwp192
    const EVP_CIPHER *cipher_belt_dwp192 = EVP_get_cipherbyname("belt-dwp192");
    if (cipher_belt_dwp192) {
        printf("Algorithm belt-dwp192 is available.\n");
    } else {
        printf("Algorithm belt-dwp192 is not available.\n");
    }

    // Проверка наличия алгоритма belt-dwp256
    const EVP_CIPHER *cipher_belt_dwp256 = EVP_get_cipherbyname("belt-dwp256");
    if (cipher_belt_dwp256) {
        printf("Algorithm belt-dwp256 is available.\n");
    } else {
        printf("Algorithm belt-dwp256 is not available.\n");
    }
    // Создать SSL_CTX с вашим собственным движком
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    if (!ctx)
    {
        fprintf(stderr, "Failed to create SSL_CTX.\n");
        return 1;
    }

    // Установить ваш собственный движок в SSL_CTX
    
    if (!SSL_CTX_set_cipher_list(ctx, EVP_belt_ctrt()))
    {
        fprintf(stderr, "Failed to set cipher list.\n");
        SSL_CTX_free(ctx);
        return 1;
    }
    // Дополнительная конфигурация SSL_CTX (если необходимо)
    // ...

    // Использовать SSL_CTX для создания SSL объекта и дальнейшей настройки соединения
    // ...

    // Освободить ресурсы
    SSL_CTX_free(ctx);
    ENGINE_cleanup();
    EVP_cleanup();

    return 0;
}
