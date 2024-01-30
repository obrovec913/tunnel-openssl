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
#include <sys/time.h>

#define PORT 12345
#define MAX_BUFFER_SIZE 2024
#define CHUNK_SIZE 1024

const unsigned char *key = (const unsigned char *)"0123456789ABCDEF";
const unsigned char *iv = (const unsigned char *)"FEDCBA9876543210";

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
    if ((ctx = SSL_CTX_new(SSLv23_client_method())) == NULL)
        handleErrors();

    // Загрузка корневого сертификата
    if (SSL_CTX_load_verify_locations(ctx, "./keys/root_cert.pem", NULL) != 1)
        handleErrors();

    // Загрузка сертификата и ключа клиента
    if (SSL_CTX_use_certificate_file(ctx, "./keys/client_cert.pem", SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, "./keys/client_key.pem", SSL_FILETYPE_PEM) != 1)
        handleErrors();

    // Проверка правильности ключа
    if (SSL_CTX_check_private_key(ctx) != 1)
        handleErrors();

    return ctx;
}

void printProgressBar(int progress, int total)
{
    const int barWidth = 70;
    float percentage = (float)progress / total;
    int pos = (int)(barWidth * percentage);

    printf("[");
    for (int i = 0; i < barWidth; ++i)
    {
        if (i < pos)
        {
            printf("=");
        }
        else if (i == pos)
        {
            printf(">");
        }
        else
        {
            printf(" ");
        }
    }
    printf("] %.2f%%\r", percentage * 100.0);
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

    // Создание и инициализация контекста шифрования
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handleErrors();

    // Получение алгоритма шифрования belt-cbc128
    const EVP_CIPHER *cipher = EVP_get_cipherbyname("belt-cbc128");
    if (!cipher)
        handleErrors();

    // Создание SSL контекста
    SSL_CTX *ssl_ctx = createSSLContext();

    // Устанавливаем соединение с сервером
    int sockfd;
    struct sockaddr_in server_addr;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        handleErrors();

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr("192.168.1.5");

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        handleErrors();

    // Создание SSL структуры
    SSL *ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, sockfd);

    // Устанавливаем SSL соединение
    if (SSL_connect(ssl) != 1)
        handleErrors();

    // Открываем файл для чтения
    FILE *file = fopen("test_data.txt", "r");
    if (!file)
    {
        fprintf(stderr, "Failed to open test_data.txt.\n");
        handleErrors();
    }

    // Получаем размер файла
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Выделяем буфер для данных файла
    unsigned char *file_data = (unsigned char *)malloc(file_size);
    if (!file_data)
    {
        fprintf(stderr, "Failed to allocate memory.\n");
        handleErrors();
    }

    // Читаем данные файла
    size_t bytes_read = fread(file_data, 1, file_size, file);

    // Инициализируем контекст шифрования
    if (EVP_EncryptInit_ex(ctx, cipher, engine, NULL, NULL) != 1)
        handleErrors();

    // Выделяем буфер для зашифрованных данных
    unsigned char *encrypted_chunk = (unsigned char *)malloc(CHUNK_SIZE + EVP_CIPHER_block_size(cipher));
    if (!encrypted_chunk)
    {
        fprintf(stderr, "Failed to allocate memory.\n");
        handleErrors();
    }

    int encrypted_len;

    // Отправляем размер файла
    if (SSL_write(ssl, &file_size, sizeof(file_size)) <= 0)
    {
        handleErrors();
    }

    // Отправляем размер блока
    if (SSL_write(ssl, &CHUNK_SIZE, sizeof(CHUNK_SIZE)) <= 0)
    {
        handleErrors();
    }

    // Отправляем данные частями с прогресс-баром
    for (size_t offset = 0; offset < bytes_read; offset += CHUNK_SIZE)
    {
        size_t chunk_size = (offset + CHUNK_SIZE <= bytes_read) ? CHUNK_SIZE : (bytes_read - offset);

        // Шифруем данные
        if (EVP_EncryptUpdate(ctx, encrypted_chunk, &encrypted_len, file_data + offset, chunk_size) != 1)
        {
            handleErrors();
        }

        int final_len;
        if (EVP_EncryptFinal_ex(ctx, encrypted_chunk + encrypted_len, &final_len) != 1)
        {
            handleErrors();
        }

        encrypted_len += final_len;

        // Отправляем размер текущего блока
        if (SSL_write(ssl, chunk_size, sizeof(chunk_size)) <= 0)
        {
            handleErrors();
        }

        // Отправляем зашифрованные данные на сервер
        if (SSL_write(ssl, encrypted_chunk, encrypted_len) <= 0)
        {
            handleErrors();
        }

        printProgressBar(offset + chunk_size, bytes_read);
    }

    fclose(file);
    free(file_data);
    free(encrypted_chunk);

    /*

    // Получаем зашифрованный ответ от сервера
    unsigned char encrypted_response[MAX_BUFFER_SIZE];
    int encrypted_response_len = SSL_read(ssl, encrypted_response, sizeof(encrypted_response));

    // Выводим зашифрованный ответ
    printf("\nEncrypted Response: ");
    for (int i = 0; i < encrypted_response_len; i++) {
        printf("%02x ", encrypted_response[i]);
    }
    printf("\n");

    // Расшифровываем ответ
    unsigned char decrypted_response[MAX_BUFFER_SIZE];
    int decrypted_len;

    // Инициализируем контекст шифрования для расшифровки
    if (EVP_DecryptInit_ex(ctx, cipher, engine, NULL, NULL) != 1)
        handleErrors();

    // Расшифровываем данные
    if (EVP_DecryptUpdate(ctx, decrypted_response, &decrypted_len, encrypted_response, encrypted_response_len) != 1)
        handleErrors();

    int final_dec_len;
    if (EVP_DecryptFinal_ex(ctx, decrypted_response + decrypted_len, &final_dec_len) != 1)
        handleErrors();

    decrypted_len += final_dec_len;
    decrypted_response[decrypted_len] = '\0';

    // Выводим расшифрованный ответ
    printf("Decrypted Response: %s\n", decrypted_response);*/

    // Завершаем соединение
    SSL_shutdown(ssl);
    close(sockfd);
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);

    return 0;
}
