#include <openssl/ssl.h>

SSL_CTX *create_ssl_context() {
    SSL_CTX *ctx;
    
    // Инициализация OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Создание контекста SSL
    ctx = SSL_CTX_new(TLSv1_2_method());

    // Загрузка сертификатов, ключей, параметров и т.д. если требуется

    // Установка параметров алгоритмов шифрования
    SSL_CTX_set_cipher_list(ctx, "DHT-PSK-BIGN-WITH-BELT-CTR-MAC-HBELT:\
        DHE-PSK-BIGN-WITH-BELT-CTR-MAC-HBELT:\
        DHT-BIGN-WITH-BELT-CTR-MAC-HBELT");

    // Установка параметров для ключа
//    SSL_CTX_set_psk_client_callback(ctx, psk_client_cb);
    // Здесь psk_client_cb - функция, которая возвращает предварительно распределенный ключ (PSK)

    return ctx;
}

int main() {
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG, NULL);
    SSL_CTX *ctx;
    SSL *ssl;
    // Инициализация SSL контекста
    ctx = create_ssl_context();
    
    // Создание SSL структуры
    ssl = SSL_new(ctx);

    // Установка соединения (например, установка сокета и вызов SSL_connect())

    // Отправка/получение данных через SSL соединение (например, с помощью SSL_read() и SSL_write())

    // Закрытие соединения и освобождение ресурсов
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return 0;
}
