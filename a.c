#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

int main()
{
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN |
                            OPENSSL_INIT_LOAD_CONFIG,
                        NULL);
    CONF_METHOD *conf_method = NCONF_default();

    const char *cipher_name = "belt-cbc128";
    SSL_CTX *ssl_ctx;
    SSL *ssl;

    // Инициализация OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Проверка наличия алгоритма шифрования
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipher_name);
    if (!cipher)
    {
        fprintf(stderr, "Алгоритм шифрования %s недоступен.\n", cipher_name);
        return EXIT_FAILURE;
    }

    // Создание SSL контекста
    ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ssl_ctx)
    {
        fprintf(stderr, "Не удалось создать SSL контекст.\n");
        return EXIT_FAILURE;
    }

    // Установка алгоритма шифрования
    if (SSL_CTX_set_cipher_list(ssl_ctx, cipher_name) != 1)
    {
        fprintf(stderr, "Не удалось установить алгоритм шифрования.\n");
        SSL_CTX_free(ssl_ctx);
        return EXIT_FAILURE;
    }
    // Установка списка наборов шифров
    const char *ciphersuites = "belt-ecb128:belt-ecb192:belt-ecb256:"
                               "belt-cbc128:belt-cbc192:belt-cbc256:"
                               "belt-cfb128:belt-cfb192:belt-cfb256:"
                               "belt-ctr128:belt-ctr192:belt-ctr256:"
                               "belt-dwp128:belt-dwp192:belt-dwp256";
    if (SSL_CTX_set_ciphersuites(ssl_ctx, ciphersuites) != 1)
    {
        // Обработка ошибки
        fprintf(stderr, "Failed to set ciphersuites\n");
        exit(1);
    }

    // Создание SSL объекта
    ssl = SSL_new(ssl_ctx);
    if (!ssl)
    {
        fprintf(stderr, "Не удалось создать SSL объект.\n");
        SSL_CTX_free(ssl_ctx);
        return EXIT_FAILURE;
    }

    // Установка SSL контекста для SSL объекта
    SSL_set_SSL_CTX(ssl, ssl_ctx);

    // Установка соединения
    if (SSL_connect(ssl) != 1)
    {
        fprintf(stderr, "Не удалось установить SSL соединение.\n");
        SSL_free(ssl);
        SSL_CTX_free(ssl_ctx);
        return EXIT_FAILURE;
    }

    // Теперь вы можете использовать SSL объект для шифрования и дешифрования данных

    // Освобождение ресурсов
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);

    return EXIT_SUCCESS;
}
