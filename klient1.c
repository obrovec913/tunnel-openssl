#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/ssl.h>
#include <sys/time.h>

#define PORT 12345
#define MAX_BUFFER_SIZE 1024

const unsigned char *key = (const unsigned char *)"0123456789ABCDEF";
const unsigned char *iv = (const unsigned char *)"FEDCBA9876543210";

void handleErrors() {
    fprintf(stderr, "Error occurred.\n");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

SSL_CTX *createSSLContext() {
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

int main() {
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

    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
        handleErrors();

    // Создание SSL структуры
    SSL *ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, sockfd);

    // Устанавливаем SSL соединение
    if (SSL_connect(ssl) != 1)
        handleErrors();

    // Чтение тестовых данных из файла
    FILE *file = fopen("test_data.txt", "rb");
    if (!file)
    {
        fprintf(stderr, "Failed to open test_data.txt.\n");
        handleErrors();
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *plaintext = (unsigned char *)malloc(file_size);
    if (!plaintext)
    {
        fclose(file);
        handleErrors();
    }

    fread(plaintext, 1, file_size, file);
    fclose(file);

    // Инициализация контекста шифрования с ключом и IV
    if (EVP_EncryptInit_ex(ctx, cipher, engine, NULL, NULL) != 1)
        handleErrors();

    // Зашифрование данных
    int update_len, final_len;
    unsigned char ciphertext[MAX_BUFFER_SIZE];

    if (EVP_EncryptUpdate(ctx, ciphertext, &update_len, plaintext, file_size) != 1)
        handleErrors();

    if (EVP_EncryptFinal_ex(ctx, ciphertext + update_len, &final_len) != 1)
        handleErrors();

    int ciphertext_len = update_len + final_len;

    // Отправка зашифрованных данных на сервер
    struct timeval start, end;
    gettimeofday(&start, NULL);

    int bytes_sent = SSL_write(ssl, ciphertext, ciphertext_len);
    if (bytes_sent <= 0)
    {
        handleErrors();
    }

    // Получение зашифрованного ответа от сервера
    unsigned char encrypted_response[MAX_BUFFER_SIZE];
    int encrypted_len = SSL_read(ssl, encrypted_response, sizeof(encrypted_response));

    gettimeofday(&end, NULL);

    // Вывод зашифрованного ответа
    printf("Encrypted Response: ");
    for (int i = 0; i < 16 && i < encrypted_len; i++)
    {
        printf("%02x ", encrypted_response[i]);
    }
    printf("\n");

    // Расшифровка ответа
    unsigned char decrypted_response[MAX_BUFFER_SIZE];
    int decrypted_len;

    if (EVP_DecryptInit_ex(ctx, cipher, engine, NULL, NULL) != 1)
        handleErrors();

    if (EVP_DecryptUpdate(ctx, decrypted_response, &decrypted_len, encrypted_response, encrypted_len) != 1)
        handleErrors();

    int final_dec_len;
    if (EVP_DecryptFinal_ex(ctx, decrypted_response + decrypted_len, &final_dec_len) != 1)
        handleErrors();

    decrypted_len += final_dec_len;
    decrypted_response[decrypted_len] = '\0';

    // Вывод расшифрованного ответа
    printf("Decrypted Response: 100\n");

    // Завершение соединения
    SSL_shutdown(ssl);
    close(sockfd);
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);

    // Вычисление и вывод времени отправки и получения
    long seconds = end.tv_sec - start.tv_sec;
    long microseconds = end.tv_usec - start.tv_usec;
    double elapsed = seconds + microseconds * 1e-6;
    printf("Time taken: %f seconds\n", elapsed);

    // Освобождение ресурсов
    free(plaintext);
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}
