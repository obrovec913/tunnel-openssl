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
int server_clok;

// Определяем возможные типы событий
enum LogType {
    INFO,
    WARNING,
    ERROR
};

// Функция для записи события в лог
void logEvent(enum LogType type, const char *format, ...) {
    // Открываем файл лога для добавления записи
    FILE *logfile = fopen("klient.log", "a");
    if (logfile == NULL) {
        perror("Failed to open log file");
        exit(EXIT_FAILURE);
    }
    
    // Получаем текущее время
    time_t rawtime;
    struct tm *timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    
    // Форматируем строку для временного штампа
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);
    
    // Определяем строку префикса в зависимости от типа события
    const char *prefix;
    switch(type) {
        case INFO:
            prefix = "[INFO]";
            break;
        case WARNING:
            prefix = "[WARNING]";
            break;
        case ERROR:
            prefix = "[ERROR]";
            break;
        default:
            prefix = "[UNKNOWN]";
    }
    
    // Форматируем строку сообщения
    va_list args;
    va_start(args, format);
    char message[1024];
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    // Записываем событие в лог
    fprintf(logfile, "[%s] %s: %s\n", timestamp, prefix, message);
    
    // Если тип события - ошибка, записываем также информацию об ошибке OpenSSL
    if (type == ERROR) {
        ERR_print_errors_fp(logfile);
    }
    
    // Закрываем файл
    fclose(logfile);
}

void handleErrors(const char *message)
{
    logEvent(ERROR, "Error occurred: %s", message);
    fprintf(stderr, "Error occurred: %s\n", message);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

SSL_CTX *createSSLContext()
{
    logEvent(INFO, "Creating SSL context");
    SSL_CTX *ctx;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    if ((ctx = SSL_CTX_new(SSLv23_client_method())) == NULL)
        handleErrors("Failed to create SSL context");

    if (SSL_CTX_load_verify_locations(ctx, "./keys/root_cert.pem", NULL) != 1)
        handleErrors("Failed to load root certificate");

    if (SSL_CTX_use_certificate_file(ctx, "./keys/client_cert.pem", SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, "./keys/client_key.pem", SSL_FILETYPE_PEM) != 1)
        handleErrors("Failed to load client certificate or key");

    if (SSL_CTX_check_private_key(ctx) != 1)
        handleErrors("Client private key check failed");

    return ctx;
}

void setupUnencryptedSocket()
{
    logEvent(INFO, "Setting up unencrypted socket");
    struct sockaddr_in unencrypted_serv_addr;

    if ((unencrypted_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        handleErrors("Failed to create unencrypted socket");

    // Опция для повторного использования адреса
    int enable = 1;
    if (setsockopt(unencrypted_sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
        handleErrors("Failed to set socket option for unencrypted socket");

    memset(&unencrypted_serv_addr, 0, sizeof(unencrypted_serv_addr));
    unencrypted_serv_addr.sin_family = AF_INET;
    unencrypted_serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    unencrypted_serv_addr.sin_port = htons(UNENCRYPTED_PORT);

    if (bind(unencrypted_sockfd, (struct sockaddr *)&unencrypted_serv_addr, sizeof(unencrypted_serv_addr)) < 0)
        handleErrors("Failed to bind unencrypted socket");

    if (listen(unencrypted_sockfd, 1) < 0)
        handleErrors("Failed to listen on unencrypted socket");
}

SSL *establishEncryptedConnection()
{
    logEvent(INFO, "Establishing encrypted connection");
    SSL_CTX *ssl_ctx = createSSLContext();
    SSL *ssl;

    int encrypted_sockfd;
    struct sockaddr_in encrypted_serv_addr;

    if ((encrypted_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        handleErrors("Failed to create socket for encrypted connection");

    memset(&encrypted_serv_addr, 0, sizeof(encrypted_serv_addr));
    encrypted_serv_addr.sin_family = AF_INET;
    encrypted_serv_addr.sin_port = htons(ENCRYPTED_PORT);
    encrypted_serv_addr.sin_addr.s_addr = inet_addr("192.168.1.5"); // Замените на IP вашего сервера

    if (connect(encrypted_sockfd, (struct sockaddr *)&encrypted_serv_addr, sizeof(encrypted_serv_addr)) < 0)
        handleErrors("Failed to connect to encrypted port");

    ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, encrypted_sockfd);

    if (SSL_connect(ssl) != 1)
        handleErrors("Failed to establish SSL connection");

    return ssl;
}

// Функция для создания сокета и установки соединения на незашифрованный порт
int connectUnencryptedPort()
{
    logEvent(INFO, "Connecting to unencrypted port");
    int unsecured_sockfd;
    struct sockaddr_in unsecured_server_addr;

    if ((unsecured_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        handleErrors("Failed to create socket for unencrypted port");

    memset(&unsecured_server_addr, 0, sizeof(unsecured_server_addr));
    unsecured_server_addr.sin_family = AF_INET;
    unsecured_server_addr.sin_port = htons(UNENCRYPTED_PORT);
    unsecured_server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(unsecured_sockfd, (struct sockaddr *)&unsecured_server_addr, sizeof(unsecured_server_addr)) < 0)
        handleErrors("Failed to connect to unencrypted port");

    return unsecured_sockfd;
}

void decryptAndProcessData(const char *data, int data_len)
{
    logEvent(INFO, "Decrypting and processing data");
    // Выделяем буфер для расшифрованных данных
    // Расшифровываем данные
    ENGINE *engine = ENGINE_by_id("bee2evp");
    if (!engine)
    {
        handleErrors("Failed to load bee2evp engine");
    }
    printf("Received encrypted data. Establishing encrypted. \n");

    // Получение алгоритма шифрования belt-cbc128
    const EVP_CIPHER *cipher = EVP_get_cipherbyname("belt-cbc128");
    if (!cipher)
        handleErrors("Failed to get cipher");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (EVP_DecryptInit_ex(ctx, EVP_get_cipherbyname("belt-cbc128"), engine, NULL, NULL) != 1)
        handleErrors("Failed to initialize decryption");

    unsigned char decrypted_data[MAX_BUFFER_SIZE];
    int decrypted_len;

    // Расшифровка данных
    if (EVP_DecryptUpdate(ctx, decrypted_data, &decrypted_len, data, data_len) != 1)
        handleErrors("Decryption update failed");

    int final_len;
    if (EVP_DecryptFinal_ex(ctx, decrypted_data + decrypted_len, &final_len) != 1)
        handleErrors("Decryption finalization failed");

    decrypted_len += final_len;
    printf("Decrypted data: %s\n", decrypted_data);
    // Отправляем расшифрованные данные на не защищенный порт
    // Отправляем расшифрованные данные

    // close(unencrypted_sockfd);
    int unsecured_sockfd = connectUnencryptedPort();

    if (send(unsecured_sockfd, decrypted_data, decrypted_len, 0) < 0)
        handleErrors("Failed to send decrypted data");

    close(unsecured_sockfd);
    memset(decrypted_data, 0, sizeof(decrypted_data));
    EVP_CIPHER_CTX_free(ctx);
}

// Шифрование данных и отправка на сервер
void encryptAndSendData(SSL *ssl, const char *data, int data_len)
{
    logEvent(INFO, "Encrypting and sending data");
    unsigned char ciphertext[MAX_BUFFER_SIZE];
    int ciphertext_len;
    int update_len, final_len;
    ENGINE *engine = ENGINE_by_id("bee2evp");
    if (!engine)
    {
        handleErrors("Failed to load bee2evp engine");
    }
    printf("Received encrypted data. Establishing encrypted. \n");

    // Получение алгоритма шифрования belt-cbc128
    const EVP_CIPHER *cipher = EVP_get_cipherbyname("belt-cbc128");
    if (!cipher)
        handleErrors("Failed to get cipher");

    // Инициализация контекста шифрования с ключом и IV
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (EVP_EncryptInit_ex(ctx, cipher, engine, NULL, NULL) != 1)
        handleErrors("Failed to initialize encryption");

    // Зашифрование данных
    if (EVP_EncryptUpdate(ctx, ciphertext, &update_len, (unsigned char *)data, data_len) != 1)
        handleErrors("Encryption update failed");

    if (EVP_EncryptFinal_ex(ctx, ciphertext + update_len, &final_len) != 1)
        handleErrors("Encryption finalization failed");

    ciphertext_len = update_len + final_len;
    printf("Encrypted Text: ");
    for (int i = 0; i < ciphertext_len; i++)
    {
        printf("%02x ", ciphertext[i]);
    }
    printf("\n");

    // Отправка зашифрованных данных на сервер
    if (SSL_write(ssl, ciphertext, ciphertext_len) <= 0)
        handleErrors("Failed to write encrypted data");

    memset(ciphertext, 0, sizeof(ciphertext));
    EVP_CIPHER_CTX_free(ctx);
}

void *receiveThreadFunction(void *arg)
{
    logEvent(INFO, "Receive thread started");
    char buffer[MAX_BUFFER_SIZE];
    int bytes_received;

    while (1)
    {
        int unencrypted_connfd = accept(unencrypted_sockfd, NULL, NULL);
        if (unencrypted_connfd < 0)
            handleErrors("Failed to accept unencrypted connection");

        bytes_received = recv(unencrypted_connfd, buffer, sizeof(buffer), 0);

        if (bytes_received > 0)
        {
            if (server_clok == 0)
            {
                logEvent(INFO, "Establishing encrypted connection");
                ssl = establishEncryptedConnection();
                server_clok = 1;
            }
            encryptAndSendData(ssl, buffer, bytes_received);

            // Очистка буфера
            memset(buffer, 0, sizeof(buffer));
            close(unencrypted_connfd);
            break;
        }
    }

    logEvent(INFO, "Receive thread exiting");
    pthread_exit(NULL);
}

void *sendThreadFunction(void *arg)
{
    logEvent(INFO, "Send thread started");
    char buffer[MAX_BUFFER_SIZE];
    int bytes_received;

    while (1)
    {
        // Принятие зашифрованных данных от сервера
        bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes_received > 0)
        {
            printf("Received encrypted data from server.\n");
            for (int i = 0; i < bytes_received; i++)
            {
                printf("%02x ", buffer[i]);
            }
            printf("\n");
            decryptAndProcessData(buffer, bytes_received);
            // Очистка буфера
            memset(buffer, 0, sizeof(buffer));
            break;
        }
    }

    logEvent(INFO, "Send thread exiting");
    pthread_exit(NULL);
}

int main()
{
    logEvent(INFO, "Application started");
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG, NULL);

    ENGINE *engine_list = ENGINE_get_first();
    while (engine_list != NULL)
    {
        printf("Доступный движок: %s\n", ENGINE_get_id(engine_list));
        engine_list = ENGINE_get_next(engine_list);
    }
    server_clok = 0;

    while (1)
    {
        setupUnencryptedSocket();
        if (pthread_create(&receiveThread, NULL, receiveThreadFunction, NULL) != 0)
        {
            fprintf(stderr, "Failed to create receive thread.\n");
            handleErrors("Failed to create receive thread");
        }
        pthread_join(receiveThread, NULL);
        close(unencrypted_sockfd);

        if (pthread_create(&sendThread, NULL, sendThreadFunction, NULL) != 0)
        {
            fprintf(stderr, "Failed to create send thread.\n");
            handleErrors("Failed to create send thread");
        }

        pthread_join(sendThread, NULL);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(createSSLContext());

    logEvent(INFO, "Application exiting");
    return 0;
}
