#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/ssl.h>
#include <pthread.h>

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

oid decryptAndProcessData(SSL *ssl, EVP_CIPHER_CTX *ctx)
{
    // Получаем размер данных от клиента
    size_t encrypted_data_size;
    if (SSL_read(ssl, &encrypted_data_size, sizeof(encrypted_data_size)) <= 0)
    {
        handleErrors();
    }
    printf("Received encrypted data size: %zu\n", encrypted_data_size);

    unsigned char *encrypted_data = (unsigned char *)malloc(encrypted_data_size);
    if (!encrypted_data)
    {
        fprintf(stderr, "Memory allocation failed.\n");
        exit(EXIT_FAILURE);
    }

    // Принимаем зашифрованные данные целиком
    size_t total_received = 0;
    while (total_received < encrypted_data_size)
    {
        size_t bytes_received = SSL_read(ssl, encrypted_data + total_received, encrypted_data_size - total_received);
        if (bytes_received <= 0)
        {
            handleErrors();
        }
        total_received += bytes_received;
    }

    printf("\nReceived %zu bytes of encrypted data.\n", total_received);

    // Выделяем буфер для расшифрованных данных
    unsigned char *decrypted_data = (unsigned char *)malloc(total_received + EVP_CIPHER_block_size(EVP_get_cipherbyname("belt-cbc128")));
    if (!decrypted_data)
    {
        fprintf(stderr, "Memory allocation failed.\n");
        exit(EXIT_FAILURE);
    }

    int decrypted_len;

    // Дешифруем данные
    if (EVP_DecryptUpdate(ctx, decrypted_data, &decrypted_len, encrypted_data, total_received) != 1)
    {
        handleErrors();
    }

    // Завершаем процесс дешифрации
    int final_len;
    if (EVP_DecryptFinal_ex(ctx, decrypted_data + decrypted_len, &final_len) != 1)
    {
        handleErrors();
    }

    decrypted_len += final_len;

    printf("Decrypted data: %s\n", decrypted_data);

    // Отправляем расшифрованные данные на не защищенный порт
    int unsecured_sockfd;
    struct sockaddr_in unsecured_server_addr;

    if ((unsecured_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        handleErrors();

    memset(&unsecured_server_addr, 0, sizeof(unsecured_server_addr));
    unsecured_server_addr.sin_family = AF_INET;
    unsecured_server_addr.sin_port = htons(5512); // Порт 5512
    unsecured_server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // Адрес localhost

    if (connect(unsecured_sockfd, (struct sockaddr *)&unsecured_server_addr, sizeof(unsecured_server_addr)) < 0)
        handleErrors();

    // Отправляем расшифрованные данные
    if (send(unsecured_sockfd, decrypted_data, decrypted_len, 0) < 0)
        handleErrors();

    // Закрываем сокет
    close(unsecured_sockfd);

    // Освобождаем память
    free(encrypted_data);
    free(decrypted_data);
}

// Функция для расшифровки данных и их обработки
void *handleConnection(void *arg)
{
    SSL *ssl = (SSL *)arg;
    ENGINE *engine = ENGINE_by_id("bee2evp");
    if (!engine)
    {
        fprintf(stderr, "Failed to load bee2evp engine: %s\n", ERR_error_string(ERR_get_error(), NULL));
        handleErrors();
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handleErrors();

    if (EVP_DecryptInit_ex(ctx, EVP_get_cipherbyname("belt-cbc128"), engine, NULL, NULL) != 1)
        handleErrors();

    // Расшифровка данных и обработка
    // (вызывайте здесь вашу функцию обработки данных)
    decryptAndProcessData(ssl, ctx);

    // Завершение работы
    EVP_CIPHER_CTX_free(ctx);
    SSL_free(ssl);
    pthread_exit(NULL);
}

int main()
{
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN |
                            OPENSSL_INIT_LOAD_CONFIG,
                        NULL);

    // Получаем список всех доступных движков
    ENGINE *engine_list = ENGINE_get_first();
    while (engine_list != NULL)
    {
        printf("Доступный движок: %s\n", ENGINE_get_id(engine_list));
        engine_list = ENGINE_get_next(engine_list);
    }

    // Создание SSL контекста
    SSL_CTX *ssl_ctx = createSSLContext();

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

        // Создаем поток для обработки соединения
        pthread_t thread;
        if (pthread_create(&thread, NULL, handleConnection, (void *)ssl) != 0)
        {
            fprintf(stderr, "Failed to create thread.\n");
            handleErrors();
        }

        // Освобождаем ресурсы потока
        pthread_detach(thread);
    }

    // Освобождение контекста шифрования
    SSL_CTX_free(ssl_ctx);

    close(sockfd);

    return 0;
}
