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
    // Создание SSL контекста с выбранным алгоритмом шифрования
    const char *cipher_name = "belt-cbc128"; // Измените на нужный алгоритм
    SSL_CTX *ssl_ctx = createSSLContext(cipher_name);

    // Установка SSL соединения
    SSL *ssl = establishEncryptedConnection(ssl_ctx);

    // Дальнейшие действия с SSL соединением

    // Освобождение ресурсов
    SSL_CTX_free(ssl_ctx);
    SSL_free(ssl);

    return 0;
}
