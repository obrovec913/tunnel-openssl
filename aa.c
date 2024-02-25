#include <openssl/ssl.h>
#include <openssl/err.h> // Добавляем заголовочный файл для работы с ошибками OpenSSL
#include <stdio.h>
#include <stdlib.h> // Добавляем заголовочный файл для функции exit()

void handle_error() {
    fprintf(stderr, "Error occurred\n");
    // Выводим подробное сообщение об ошибке OpenSSL
    ERR_print_errors_fp(stderr);
    // Можем также получить код ошибки и текстовое описание
    unsigned long err_code = ERR_get_error();
    char err_buf[256];
    ERR_error_string(err_code, err_buf);
    fprintf(stderr, "Error code: %lu, Error message: %s\n", err_code, err_buf);
    exit(EXIT_FAILURE);
}

SSL_CTX *create_ssl_context() {
    SSL_CTX *ctx;

    // Инициализация OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Создание контекста SSL
    if (!(ctx = SSL_CTX_new(TLSv1_2_method()))) {
        printf("Received from server.\n");
        handle_error();
    }

    // Установка параметров алгоритмов шифрования
    if (SSL_CTX_set_cipher_list(ctx, "DHT-PSK-BIGN-WITH-BELT-CTR-MAC-HBELT:\
        DHE-PSK-BIGN-WITH-BELT-CTR-MAC-HBELT:\
        DHT-BIGN-WITH-BELT-CTR-MAC-HBELT") != 1) {
        handle_error();
    }

    // Установка параметров для ключа
//    SSL_CTX_set_psk_client_callback(ctx, psk_client_cb);
    // Здесь psk_client_cb - функция, которая возвращает предварительно распределенный ключ (PSK)

    return ctx;
}

int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG, NULL);

    // Инициализация SSL контекста
    if (!(ctx = create_ssl_context())) {
        handle_error();
    }

    // Создание SSL структуры
    if (!(ssl = SSL_new(ctx))) {
        handle_error();
    }

    // Установка соединения (например, установка сокета и вызов SSL_connect())
    // Обработка ошибок установки соединения
    if (SSL_connect(ssl) <= 0) {
        handle_error();
    }

    // Отправка/получение данных через SSL соединение (например, с помощью SSL_read() и SSL_write())

    // Закрытие соединения и освобождение ресурсов
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return 0;
}
