#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>

// Создание SSL контекста с выбранным алгоритмом шифрования
SSL_CTX *createSSLContext(const char *cipher_name) {
    SSL_CTX *ssl_ctx = SSL_CTX_new(SSLv23_client_method()); // Используйте нужный метод SSL
    if (ssl_ctx == NULL) {
        // Обработка ошибки
    }

    // Получение алгоритма шифрования EVP
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipher_name);
    if (cipher == NULL) {
        // Обработка ошибки
    }

    // Установка алгоритма шифрования для SSL контекста
    if (!SSL_CTX_set_cipher(ssl_ctx, cipher)) {
        // Обработка ошибки
        printf("Received encrypted data. Establishing . \n");
    }

    return ssl_ctx;
}

// Установка SSL соединения с использованием созданного SSL контекста
SSL *establishEncryptedConnection(SSL_CTX *ssl_ctx) {
    // Создание SSL объекта
    SSL *ssl = SSL_new(ssl_ctx);
    if (ssl == NULL) {
        // Обработка ошибки
    }

    // Установка сокета
    int sockfd; // Должен быть инициализирован вашим сокетом
    SSL_set_fd(ssl, sockfd);

    // Установка SSL соединения
    if (SSL_connect(ssl) != 1) {
        // Обработка ошибки
    }

    return ssl;
}

int main() {
     OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG, NULL);

    ENGINE *engine_list = ENGINE_get_first();
    while (engine_list != NULL)
    {
        printf("Доступный движок: %s\n", ENGINE_get_id(engine_list));
        engine_list = ENGINE_get_next(engine_list);
    }
    // Создание SSL контекста с выбранным алгоритмом шифрования
    const char *cipher_name = "belt-cbc128"; // Измените на нужный алгоритм
    SSL_CTX *ssl_ctx = createSSLContext(cipher_name);
     printf("Received encrypted data. Establishing encrypted. \n");

    // Установка SSL соединения
    SSL *ssl = establishEncryptedConnection(ssl_ctx);

    // Дальнейшие действия с SSL соединением

    // Освобождение ресурсов
    SSL_CTX_free(ssl_ctx);
    SSL_free(ssl);

    return 0;
}
