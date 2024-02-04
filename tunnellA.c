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
#include <pthread.h>

#define UNENCRYPTED_PORT 7781
#define ENCRYPTED_PORT 12345
#define MAX_BUFFER_SIZE 2024
#define CHUNK_SIZE 1024

const unsigned char *key = (const unsigned char *)"0123456789ABCDEF";
const unsigned char *iv = (const unsigned char *)"FEDCBA9876543210";

pthread_t receiveThread, sendThread;
int unencrypted_sockfd;
SSL *ssl;

void handleErrors()
{
    fprintf(stderr, "Error occurred.\n");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

SSL_CTX *createSSLContext()
{
    SSL_CTX *ctx;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    if ((ctx = SSL_CTX_new(SSLv23_client_method())) == NULL)
        handleErrors();

    if (SSL_CTX_load_verify_locations(ctx, "./keys/root_cert.pem", NULL) != 1)
        handleErrors();

    if (SSL_CTX_use_certificate_file(ctx, "./keys/client_cert.pem", SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, "./keys/client_key.pem", SSL_FILETYPE_PEM) != 1)
        handleErrors();

    if (SSL_CTX_check_private_key(ctx) != 1)
        handleErrors();

    return ctx;
}

void setupUnencryptedSocket()
{
    struct sockaddr_in unencrypted_serv_addr;

     if ((unencrypted_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        handleErrors();

    // Опция для повторного использования адреса
    int enable = 1;
    if (setsockopt(unencrypted_sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
        handleErrors();
    memset(&unencrypted_serv_addr, 0, sizeof(unencrypted_serv_addr));
    unencrypted_serv_addr.sin_family = AF_INET;
    unencrypted_serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    unencrypted_serv_addr.sin_port = htons(UNENCRYPTED_PORT);

    if (bind(unencrypted_sockfd, (struct sockaddr *)&unencrypted_serv_addr, sizeof(unencrypted_serv_addr)) < 0)
        handleErrors();

    if (listen(unencrypted_sockfd, 1) < 0)
        handleErrors();
}

SSL *establishEncryptedConnection()
{
    SSL_CTX *ssl_ctx = createSSLContext();
    SSL *ssl;

    int encrypted_sockfd;
    struct sockaddr_in encrypted_serv_addr;

    if ((encrypted_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        handleErrors();

    memset(&encrypted_serv_addr, 0, sizeof(encrypted_serv_addr));
    encrypted_serv_addr.sin_family = AF_INET;
    encrypted_serv_addr.sin_port = htons(ENCRYPTED_PORT);
    encrypted_serv_addr.sin_addr.s_addr = inet_addr("192.168.1.5"); // Замените на IP вашего сервера

    if (connect(encrypted_sockfd, (struct sockaddr *)&encrypted_serv_addr, sizeof(encrypted_serv_addr)) < 0)
        handleErrors();

    ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, encrypted_sockfd);

    if (SSL_connect(ssl) != 1)
        handleErrors();

    return ssl;
}
void decryptAndProcessData(const char *data, int data_len)
{
    // Выделяем буфер для расшифрованных данных
    // Расшифровываем данные
    ENGINE *engine = ENGINE_by_id("bee2evp");
    if (!engine)
    {
        fprintf(stderr, "Failed to load bee2evp engine: %s\n", ERR_error_string(ERR_get_error(), NULL));
        handleErrors();
    }
    printf("Received encrypted data. Establishing encrypted. \n");

    // Получение алгоритма шифрования belt-cbc128
    const EVP_CIPHER *cipher = EVP_get_cipherbyname("belt-cbc128");
    if (!cipher)
        handleErrors();
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (EVP_DecryptInit_ex(ctx, EVP_get_cipherbyname("belt-cbc128"), engine, NULL, NULL) != 1)
        handleErrors();
    unsigned char decrypted_data[MAX_BUFFER_SIZE];
    int decrypted_len;

    // Расшифровка данных
    if (EVP_DecryptUpdate(ctx, decrypted_data, &decrypted_len, data, data_len) != 1)
        handleErrors();
    int final_len;
    if (EVP_DecryptFinal_ex(ctx, decrypted_data + decrypted_len, &final_len) != 1)
        handleErrors();

    decrypted_len += final_len;
    printf("Decrypted data: %s\n", decrypted_data);
    // Отправляем расшифрованные данные на не защищенный порт
    // Отправляем расшифрованные данные
    if (send(unencrypted_sockfd, decrypted_data, decrypted_len, 0) < 0)
        handleErrors();
    memset(decrypted_data, 0, sizeof(decrypted_data));
    EVP_CIPHER_CTX_free(ctx);
}

// Шифрование данных и отправка на сервер
void encryptAndSendData(SSL *ssl, const char *data, int data_len)
{
    unsigned char ciphertext[MAX_BUFFER_SIZE];
    int ciphertext_len;
    int update_len, final_len;
    ENGINE *engine = ENGINE_by_id("bee2evp");
    if (!engine)
    {
        fprintf(stderr, "Failed to load bee2evp engine: %s\n", ERR_error_string(ERR_get_error(), NULL));
        handleErrors();
    }
    printf("Received encrypted data. Establishing encrypted. \n");

    // Получение алгоритма шифрования belt-cbc128
    const EVP_CIPHER *cipher = EVP_get_cipherbyname("belt-cbc128");
    if (!cipher)
        handleErrors();

    // Инициализация контекста шифрования с ключом и IV
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (EVP_EncryptInit_ex(ctx, cipher, engine, NULL, NULL) != 1)
        handleErrors();

    // Зашифрование данных
    if (EVP_EncryptUpdate(ctx, ciphertext, &update_len, (unsigned char *)data, data_len) != 1)
        handleErrors();

    if (EVP_EncryptFinal_ex(ctx, ciphertext + update_len, &final_len) != 1)
        handleErrors();

    ciphertext_len = update_len + final_len;
    printf("Encrypted Text: ");
    for (int i = 0; i < ciphertext_len; i++)
    {
        printf("%02x ", ciphertext[i]);
    }
    printf("\n");

    // Отправка зашифрованных данных на сервер
    if (SSL_write(ssl, ciphertext, ciphertext_len) <= 0)
        handleErrors();
    printf("Encrypted WRITE ");
    memset(ciphertext, 0, sizeof(ciphertext));
    EVP_CIPHER_CTX_free(ctx);
}

void *receiveThreadFunction(void *arg)
{
    char buffer[MAX_BUFFER_SIZE];
    int bytes_received;

    while (1)
    {
        int unencrypted_connfd = accept(unencrypted_sockfd, NULL, NULL);
        if (unencrypted_connfd < 0)
            handleErrors();

        bytes_received = recv(unencrypted_connfd, buffer, sizeof(buffer), 0);

        if (bytes_received > 0)
        {
            printf("Received unencrypted data.\n");
            encryptAndSendData(ssl, buffer, bytes_received);
            printf("Received connection.\n");

            // Очистка буфера
            memset(buffer, 0, sizeof(buffer));
        }

        close(unencrypted_connfd);
    }

    pthread_exit(NULL);
}

void *sendThreadFunction(void *arg)
{
    char buffer[MAX_BUFFER_SIZE];
    int bytes_received;

    while (1)
    {
        // Принятие зашифрованных данных от сервера
        bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes_received > 0)
        {
            printf("Received encrypted data from server.\n");
            printf("Decrypted Text: ");
            for (int i = 0; i < bytes_received; i++)
            {
                printf("%02x ", buffer[i]);
            }
            printf("\n");
            decryptAndProcessData(buffer, bytes_received);
            // Очистка буфера
            memset(buffer, 0, sizeof(buffer));
        }
    }

    pthread_exit(NULL);
}

int main()
{
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG, NULL);

    ENGINE *engine_list = ENGINE_get_first();
    while (engine_list != NULL)
    {
        printf("Доступный движок: %s\n", ENGINE_get_id(engine_list));
        engine_list = ENGINE_get_next(engine_list);
    }

    

    ssl = establishEncryptedConnection();

    while (1)
    {
        setupUnencryptedSocket();
        if (pthread_create(&receiveThread, NULL, receiveThreadFunction, NULL) != 0)
        {
            fprintf(stderr, "Failed to create receive thread.\n");
            handleErrors();
        }
        pthread_join(receiveThread, NULL);

        

        if (pthread_create(&sendThread, NULL, sendThreadFunction, NULL) != 0)
        {
            fprintf(stderr, "Failed to create send thread.\n");
            handleErrors();
        }

        
        pthread_join(sendThread, NULL);
        close(unencrypted_sockfd);
    }

    
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(createSSLContext());

    return 0;
}
