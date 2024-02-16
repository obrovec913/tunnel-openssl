
#include <openssl/engine.h>
#include <openssl/ssl.h>

// Функция инициализации вашего собственного движка
int init_my_engine() {
    // Загрузка собственного движка
    ENGINE *my_engine = ENGINE_by_id("bee2evp");
    if (!my_engine) {
        fprintf(stderr, "Failed to load your engine.\n");
        return 0;
    }

    // Инициализация собственного движка
    if (!ENGINE_init(my_engine)) {
        fprintf(stderr, "Failed to initialize your engine.\n");
        ENGINE_free(my_engine);
        return 0;
    }

    // Зарегистрировать собственный движок
    if (!ENGINE_set_default(my_engine, ENGINE_METHOD_ALL)) {
        fprintf(stderr, "Failed to register your engine.\n");
        ENGINE_free(my_engine);
        return 0;
    }

    return 1;
}

int main() {
    // Инициализировать OpenSSL
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG, NULL);
    SSL_library_init();
    SSL_load_error_strings();
    
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();

    // Инициализация вашего собственного движка
    if (!init_my_engine()) {
        fprintf(stderr, "Failed to initialize your engine.\n");
        return 1;
    }

    // Создать SSL_CTX с вашим собственным движком
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL_CTX.\n");
        return 1;
    }

    // Установить ваш собственный движок в SSL_CTX
    if (!SSL_CTX_set_cipher_list(ctx, "belt-cbc128")) {
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
