#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <stdio.h>

// Функция для создания SSL контекста с заданным алгоритмом шифрования Bee2
SSL_CTX *createSSLContextWithBee2Cipher(const char *cipher_name) {
    // Инициализация OpenSSL
    SSL_library_init();
    SSL_load_error_strings();

    // Создание SSL контекста
    SSL_CTX *ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ssl_ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        return NULL;
    }

    // Инициализация плагина Bee2evp
    ENGINE_load_builtin_engines();
    ENGINE_register_all_complete();

    // Получение плагина Bee2evp
    ENGINE *bee2_engine = ENGINE_by_id("bee2evp");
    if (!bee2_engine) {
        fprintf(stderr, "Failed to load Bee2evp engine\n");
        return NULL;
    }

    // Запуск плагина Bee2evp
    if (!ENGINE_init(bee2_engine)) {
        fprintf(stderr, "Failed to initialize Bee2evp engine\n");
        ENGINE_free(bee2_engine);
        return NULL;
    }

    // Установка плагина Bee2evp в SSL контекст
    if (!SSL_CTX_set_cipher_list(ssl_ctx, cipher_name)) {
        fprintf(stderr, "Failed to set cipher list\n");
        ENGINE_free(bee2_engine);
        return NULL;
    }

    // Установка метода шифрования

    // Освобождение плагина Bee2evp
    ENGINE_free(bee2_engine);

    return ssl_ctx;
}

int main() {
     OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG, NULL);

    // Создание SSL контекста с заданным алгоритмом шифрования Bee2
    SSL_CTX *ssl_ctx = createSSLContextWithBee2Cipher("belt-cbc128");
    if (!ssl_ctx) {
        fprintf(stderr, "Failed to create SSL context with Bee2 cipher\n");
        return 1;
    }

    // Использование SSL контекста

    // Освобождение SSL контекста
    SSL_CTX_free(ssl_ctx);

    return 0;
}
