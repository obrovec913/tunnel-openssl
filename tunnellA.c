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

// Обработчик ошибок
void handleErrors()
{
    fprintf(stderr, "Error occurred.\n");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

// Создание контекста SSL
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

// Отображение прогресс-бара
void printProgressBar(int progress, int total)
{
    const int barWidth = 70;
    float percentage = (float)progress / total;
    int pos = (int)(barWidth * percentage);

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
    printf("] %.2f%%\r", percentage * 100.0);
    fflush(stdout);
}

// Функция потока для отправки данных
void *sendThreadFunction(void *arg)
{
    SSL *ssl = (SSL *)arg;
    char buffer[MAX_BUFFER_SIZE];
    int bytes_received;

    // Принимаем данные с незашифрованного порта и отправляем зашифрованные на сервер
    while ((bytes_received = recv(SSL_get_fd(ssl), buffer, sizeof(buffer), 0)) > 0)
    {
        // Здесь можно обработать данные перед шифрованием, если необходимо
        // В данном примере просто шифруем все принятые данные
        encryptAndSendData(ssl, buffer, bytes_received);
    }

    pthread_exit(NULL);
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

    // Отправка зашифрованных данных на сервер
    if (SSL_write(ssl, ciphertext, ciphertext_len) <= 0)
        handleErrors();

    EVP_CIPHER_CTX_free(ctx);
}
SSL sslNewConnect(int encrypted_sockfd)
{

    struct sockaddr_in encrypted_serv_addr;
    SSL_CTX *ssl_ctx = createSSLContext();

    if ((encrypted_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        handleErrors();

    memset(&encrypted_serv_addr, 0, sizeof(encrypted_serv_addr));
    encrypted_serv_addr.sin_family = AF_INET;
    encrypted_serv_addr.sin_port = htons(ENCRYPTED_PORT);
    encrypted_serv_addr.sin_addr.s_addr = inet_addr("192.168.1.5"); // Замените на IP вашего сервера

    // Установка защищенного соединения
    SSL *ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, encrypted_sockfd);

    if (connect(encrypted_sockfd, (struct sockaddr *)&encrypted_serv_addr, sizeof(encrypted_serv_addr)) < 0)
        handleErrors();

    if (SSL_connect(ssl) != 1)
        handleErrors();
    printf("Received encrypted connection.\n");
    return ssl;
}

void waitForUnencryptedData(int unencrypted_sockfd)
{
    char buffer[MAX_BUFFER_SIZE];
    int bytes_received;
    int encrypted_sockfd;
    SSL *ssl;

    while (1)
    {
        int unencrypted_connfd = accept(unencrypted_sockfd, NULL, NULL);
        if (unencrypted_connfd < 0)
            handleErrors();

        // Принимаем данные с незашифрованного порта
        bytes_received = recv(unencrypted_connfd, buffer, sizeof(buffer), 0);

        if (bytes_received > 0)
        {
            printf("Received unencrypted data. Establishing encrypted connection.\n");
            
            ssl = sslNewConnect(&encrypted_sockfd);
            encryptAndSendData(ssl, buffer, bytes_received);
            printf("Received connection.\n");
            break; // Прерываем цикл, если поступили данные на незашифрованный порт
        }

        close(unencrypted_connfd);
    }
    close(encrypted_sockfd);
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

int main()
{
    // Инициализация OpenSSL и создание контекста для защищенного соединения
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG, NULL);
    // Получаем список всех доступных движков
    ENGINE *engine_list = ENGINE_get_first();
    while (engine_list != NULL)
    {
        printf("Доступный движок: %s\n", ENGINE_get_id(engine_list));
        engine_list = ENGINE_get_next(engine_list);
    }

    // Создание структуры для незашифрованного соединения
    int unencrypted_sockfd;
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

    // Ожидание данных на незашифрованном порту перед установкой защищенного соединения
    waitForUnencryptedData(unencrypted_sockfd);

    // Закрытие соединений и освобождение ресурсов

    close(unencrypted_sockfd);
    // SSL_free(ssl);
    //   SSL_CTX_free(ssl_ctx);

    return 0;
}