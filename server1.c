#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/ssl.h>

const unsigned char *key = (const unsigned char *)"0123456789ABCDEF";
const unsigned char *iv = (const unsigned char *)"FEDCBA9876543210";

#define PORT 12345
#define MAX_BUFFER_SIZE 2024

void handleErrors()
{
    fprintf(stderr, "Error occurred.\n");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

SSL_CTX *createSSLContext()
{
    SSL_CTX *ctx;

    // Инициализация OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Создание нового SSL_CTX
    if ((ctx = SSL_CTX_new(SSLv23_server_method())) == NULL)
        handleErrors();

    // Загрузка корневого сертификата
    if (SSL_CTX_load_verify_locations(ctx, "./keys/root_cert.pem", NULL) != 1)
        handleErrors();

    // Загрузка сертификата и ключа сервера
    if (SSL_CTX_use_certificate_file(ctx, "./keys/server_cert.pem", SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, "./keys/server_key.pem", SSL_FILETYPE_PEM) != 1)
        handleErrors();

    // Проверка правильности ключа
    if (SSL_CTX_check_private_key(ctx) != 1)
        handleErrors();

    return ctx;
}

int main()
{
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN |
                            OPENSSL_INIT_LOAD_CONFIG,
                        NULL);
    CONF_METHOD *conf_method = NCONF_default();
    if (conf_method)
    {
        CONF *conf = NCONF_new(conf_method);
        if (conf)
        {
            NCONF_dump_fp(conf, stdout);
            NCONF_free(conf);
        }
        else
        {
            fprintf(stderr, "Failed to create OpenSSL configuration.\n");
        }
    }
    else
    {
        fprintf(stderr, "Failed to get OpenSSL configuration method.\n");
    }

    // Получаем список всех доступных движков
    ENGINE *engine_list = ENGINE_get_first();
    while (engine_list != NULL)
    {
        printf("Доступный движок: %s\n", ENGINE_get_id(engine_list));
        engine_list = ENGINE_get_next(engine_list);
    }

    ENGINE *engine = ENGINE_by_id("bee2evp");
    if (!engine)
    {
        fprintf(stderr, "Failed to load bee2evp engine: %s\n", ERR_error_string(ERR_get_error(), NULL));
        handleErrors();
    }

    // Создание SSL контекста
    SSL_CTX *ssl_ctx = createSSLContext();

    // Показываем пользователю доступные алгоритмы шифрования
    const EVP_CIPHER *cipher = EVP_get_cipherbyname("belt-cbc128");

    // Инициализация контекста шифрования с ключом и IV
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handleErrors();

    if (EVP_DecryptInit_ex(ctx, cipher, engine, NULL, NULL) != 1)
        handleErrors();

    // Устанавливаем серверный сокет
    int sockfd, connfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t len;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        handleErrors();

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        handleErrors();

    if (listen(sockfd, 5) < 0)
        handleErrors();

    while (1)
    { // бесконечный цикл для прослушивания порта
        len = sizeof(client_addr);
        connfd = accept(sockfd, (struct sockaddr *)&client_addr, &len);
        if (connfd < 0)
            handleErrors();

        // Создание SSL структуры
        SSL *ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, connfd);

        // Устанавливаем SSL соединение
        if (SSL_accept(ssl) != 1)
            handleErrors();

        // Получаем размер зашифрованных данных от клиента
        int total_received = 0;
        int bytes_received;

        int message_size;
        int bytes_size_received = SSL_read(ssl, &message_size, sizeof(message_size));
        if (bytes_size_received != sizeof(message_size))
        {
            fprintf(stderr, "Error reading message size.\n");
            handleErrors();
        }
        // Инициализация контекста шифрования с ключом и IV
        if (EVP_EncryptInit_ex(ctx, cipher, engine, NULL, NULL) != 1)
            handleErrors();

        // Читаем данные по частям
        while ((bytes_received = SSL_read(ssl, ciphertext + total_received, sizeof(ciphertext) - total_received)) > 0)
        {
            total_received += bytes_received;

            // Расшифровываем данные
            unsigned char decrypted_text[MAX_BUFFER_SIZE];
            int decrypted_len;

            // Расшифровка данных
            if (EVP_DecryptUpdate(ctx, decrypted_text, &decrypted_len, ciphertext, total_received) != 1)
                handleErrors();

            int final_len;
            if (EVP_DecryptFinal_ex(ctx, decrypted_text + decrypted_len, &final_len) != 1)
                handleErrors();

            decrypted_len += final_len;
            decrypted_text[decrypted_len] = '\0';

            // Вывод расшифрованного сообщения
            printf("Decrypted Text: %s\n", decrypted_text);

            // Обрабатываем данные (например, меняем местами слова)
            char processed_text[MAX_BUFFER_SIZE];
            snprintf(processed_text, MAX_BUFFER_SIZE, "Processed: %s", decrypted_text);

            // Зашифровываем обработанный ответ
            unsigned char encrypted_response[MAX_BUFFER_SIZE];
            int encrypted_len;

            if (EVP_EncryptUpdate(ctx, encrypted_response, &encrypted_len, (const unsigned char *)processed_text, strlen(processed_text)) != 1)
                handleErrors();

            int final_enc_len;
            if (EVP_EncryptFinal_ex(ctx, encrypted_response + encrypted_len, &final_enc_len) != 1)
                handleErrors();

            encrypted_len += final_enc_len;

            // Отправляем размер зашифрованного ответа
            if (SSL_write(ssl, &encrypted_len, sizeof(encrypted_len)) != sizeof(encrypted_len))
            {
                fprintf(stderr, "Error writing encrypted response size.\n");
                handleErrors();
            }

            // Отправляем зашифрованный ответ клиенту
            int total_sent = 0;
            int bytes_sent;

            // Отправляем данные по частям
            while (total_sent < encrypted_len)
            {
                bytes_sent = SSL_write(ssl, encrypted_response + total_sent, encrypted_len - total_sent);
                if (bytes_sent <= 0)
                {
                    handleErrors();
                }
                total_sent += bytes_sent;
            }

            // Очищаем буфер для следующей порции данных
            total_received = 0;
        }

        // Закрываем соединение и освобождаем ресурсы
        close(connfd);
        SSL_free(ssl);
    }

    // Освобождение контекста шифрования
    EVP_CIPHER_CTX_free(ctx);

    close(sockfd);
    SSL_CTX_free(ssl_ctx);

    return 0;
}
