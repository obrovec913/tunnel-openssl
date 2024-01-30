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
#define CHUNK_SIZE 1024

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

void printProgressBar(size_t current, size_t total)
{
    const size_t barWidth = 70;
    float progress = (float)current / (float)total;
    int pos = barWidth * progress;

    printf("[");
    for (int i = 0; i < barWidth; ++i)
    {
        if (i < pos)
            printf("=");
        else if (i == pos)
            printf(">");
        else
            printf(" ");
    }
    printf("] %.2f%%\r", progress * 100.0);
    fflush(stdout);
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

    // Инициализация контекста шифрования с ключом и IV
    const EVP_CIPHER *cipher = EVP_get_cipherbyname("belt-cbc128");
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
    {
        // бесконечный цикл для прослушивания порта
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

        printf("got server\n");

        // Получаем зашифрованные данные от клиента
        // Получаем размер файла от клиента
        size_t file_size;
        if (SSL_read(ssl, &file_size, sizeof(file_size)) <= 0)
        {
            handleErrors();
        }

        printf("Received file size: %zu\n", file_size);

        // Выделяем буфер для зашифрованных данных
        unsigned char *ciphertext = (unsigned char *)malloc(file_size);
        if (!ciphertext)
        {
            fprintf(stderr, "Memory allocation failed.\n");
            exit(EXIT_FAILURE);
        }

        // Общий буфер для приема данных частями
        unsigned char *received_data = (unsigned char *)malloc(file_size);
        if (!received_data)
        {
            fprintf(stderr, "Memory allocation failed.\n");
            exit(EXIT_FAILURE);
        }

        size_t total_received = 0;
        while (total_received < file_size)
        {
            // Принимаем размер текущего блока
            size_t chunk_size;
            if (SSL_read(ssl, &chunk_size, sizeof(chunk_size)) <= 0)
            {
                handleErrors();
            }
            printf("Received chunk: %zu\n", chunk_size);

            // Принимаем зашифрованные данные частями
            int bytes_received = SSL_read(ssl, ciphertext, chunk_size);
            if (bytes_received <= 0)
            {
                handleErrors();
            }
            printf("Received \n");

            // Дешифруем данные
            int decrypted_len;
            if (EVP_DecryptUpdate(ctx, received_data + total_received, &decrypted_len, ciphertext, bytes_received) != 1)
            {
                handleErrors();
            }
            int final_len;
            if (EVP_DecryptFinal_ex(ctx, received_data + total_received, &final_len) != 1)
            {
                handleErrors();
            }

            total_received += decrypted_len;
            total_received += final_len;

            // Выводим прогресс
            printProgressBar(total_received, file_size);
        }

        free(ciphertext);

        // Расшифровка последнего блока
        int final_len;
        if (EVP_DecryptFinal_ex(ctx, received_data + total_received, &final_len) != 1)
        {
            handleErrors();
        }

        total_received += final_len;

        printf("\nReceived %zu bytes in total.\n", total_received);

        // Обрабатываем расшифрованные данные (если нужно)

        // Освобождаем память
        free(received_data);

        // Обрабатываем данные (например, меняем местами слова)
        /*char processed_text[MAX_BUFFER_SIZE];
        snprintf(processed_text, MAX_BUFFER_SIZE, "Processed: %s", decrypted_text);

        // Зашифровываем обработанный ответ
        if (EVP_EncryptInit_ex(ctx, cipher, engine, key, iv) != 1)
            handleErrors();

        unsigned char *encrypted_response;
        int encrypted_len;

        if (EVP_EncryptUpdate(ctx, NULL, &encrypted_len, (const unsigned char *)processed_text, strlen(processed_text)) != 1)
            handleErrors();

        encrypted_response = (unsigned char *)malloc(encrypted_len);
        if (!encrypted_response)
        {
            fprintf(stderr, "Memory allocation failed.\n");
            exit(EXIT_FAILURE);
        }

        if (EVP_EncryptUpdate(ctx, encrypted_response, &encrypted_len, (const unsigned char *)processed_text, strlen(processed_text)) != 1)
            handleErrors();

        int final_enc_len;
        if (EVP_EncryptFinal_ex(ctx, encrypted_response + encrypted_len, &final_enc_len) != 1)
            handleErrors();

        encrypted_len += final_enc_len;

        // Отправляем зашифрованный ответ клиенту
        int total_sent = 0;
        int bytes_sent;

        // Отправляем длину зашифрованных данных
        bytes_sent = SSL_write(ssl, &encrypted_len, sizeof(encrypted_len));
        if (bytes_sent <= 0)
        {
            handleErrors();
        }*/

        // Отправляем сами зашифрованные данные частями с прогресс-баром
        /*for (size_t offset = 0; offset < encrypted_len; offset += CHUNK_SIZE) {
            size_t chunk_size = (offset + CHUNK_SIZE <= encrypted_len) ? CHUNK_SIZE : (encrypted_len - offset);

            // Отправляем зашифрованные данные на сервер
            bytes_sent = SSL_write(ssl, encrypted_response + offset, chunk_size);
            if (bytes_sent <= 0) {
                handleErrors();
            }

            printProgressBar(offset + chunk_size, encrypted_len);
        }*/

        // Освобождаем память
        // free(encrypted_response);
        printf("\nEncrypted Response: ");

        // Освобождаем память
        free(ciphertext);

        close(connfd);
        SSL_free(ssl);
    }

    // Освобождение контекста шифрования
    EVP_CIPHER_CTX_free(ctx);

    close(sockfd);
    SSL_CTX_free(ssl_ctx);

    return 0;
}