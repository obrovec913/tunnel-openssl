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

    setupUnencryptedSocket();

    ssl = establishEncryptedConnection();

    while (1)
    {
        if (pthread_create(&receiveThread, NULL, receiveThreadFunction, NULL) != 0)
        {
            fprintf(stderr, "Failed to create receive thread.\n");
            handleErrors();
        }

        if (pthread_create(&sendThread, NULL, sendThreadFunction, NULL) != 0)
        {
            fprintf(stderr, "Failed to create send thread.\n");
            handleErrors();
        }

        pthread_join(receiveThread, NULL);
        pthread_join(sendThread, NULL);
    }

    close(unencrypted_sockfd);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(createSSLContext());

    return 0;
}
