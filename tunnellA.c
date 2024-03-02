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
#define PSK_KEY "123456"
#define PSK_HINT "123"
#define CLIENT_KEY_FILE "./keys/bign-curve256v1.key" // Путь к файлу с закрытым ключом клиента
#define CLIENT_CERT_FILE "./keys/client_cert.pem"    // Путь к файлу с сертификатом клиента

pthread_t receiveThread, sendThread;
int unencrypted_sockfd;
SSL *ssl;
int server_clok;
fd_set readfds;
int unencrypted_connfd;
// Определяем возможные типы событий
enum LogType
{
    INFO,
    WARNING,
    ERROR
};

// Функция для записи события в лог
void logEvent(enum LogType type, const char *format, ...)
{
    // Открываем файл лога для добавления записи
    FILE *logfile = fopen("klient.log", "a");
    if (logfile == NULL)
    {
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
    switch (type)
    {
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
    if (type == ERROR)
    {
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

int psk_client_callback(SSL *ssl, const char *hint, char *identity, unsigned int max_identity_len, unsigned char *psk, unsigned int max_psk_len)
{
    strncpy((char *)psk, PSK_KEY, max_psk_len);
    return strlen(PSK_KEY);
}

void info_callback(const SSL *ssl, int type, int val)
{
    if (type & SSL_CB_ALERT)
    {
        fprintf(stderr, "SSL/TLS ALERT: %s:%s:%s\n", SSL_alert_type_string_long(val),
                SSL_alert_desc_string_long(val), SSL_alert_desc_string(val));
    }
    else if (type & SSL_CB_HANDSHAKE_START)
    {
        fprintf(stderr, "SSL/TLS HANDSHAKE начат\n");
    }
    else if (type & SSL_CB_HANDSHAKE_DONE)
    {
        fprintf(stderr, "SSL/TLS HANDSHAKE завершен\n");
    }
    else
    {
        fprintf(stderr, "SSL/TLS INFO: %s\n", SSL_state_string_long(ssl));
    }
}

SSL_CTX *createSSLContext()
{
    logEvent(INFO, "Creating SSL context");
    SSL_CTX *ctx;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    if (!(ctx = SSL_CTX_new(TLSv1_2_client_method())))
    {
        printf("Failed to create SSL context\n");
        handleErrors("Failed to create SSL context");
    }
    SSL_CTX_set_info_callback(ctx, info_callback);

    // Установка параметров алгоритмов шифрования
    if (SSL_CTX_set_cipher_list(ctx, "DHE-BIGN-WITH-BELT-DWP-HBELT") != 1)
    {
        handleErrors("Failed to load Cipher");
    }

    // Загрузка PSK
    SSL_CTX_set_psk_client_callback(ctx, psk_client_callback);

    // Загрузка корневого сертификата сервера (если необходимо)
    // SSL_CTX_load_verify_locations(ctx, "server.crt", NULL);

    // Загрузка сертификата клиента
    // SSL_CTX_use_certificate_file(ctx, CLIENT_CERT_FILE, SSL_FILETYPE_PEM);

    // if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERT_FILE, SSL_FILETYPE_PEM) != 1 ||
    // SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY_FILE, SSL_FILETYPE_PEM) != 1)
    // handleErrors("Failed to load client certificate or key");

    // if (SSL_CTX_check_private_key(ctx) != 1)
    //   handleErrors("Client private key check failed");

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
     int unencrypted_connfd = accept(unencrypted_sockfd, NULL, NULL);
        if (unencrypted_connfd < 0)
            handleErrors("Failed to accept unencrypted connection");

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

    printf("подключился  сервер: \n");

    return ssl;
}

void *handle_connection(void *data)
{
    int *sockets = (int *)data;
    int unencrypted_connfd = sockets[0];
    SSL *ssl = (SSL *)(intptr_t)sockets[1];

    char buffer[MAX_BUFFER_SIZE];
    int bytes_received;

    while (1)
    {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(unencrypted_connfd, &readfds);
        FD_SET(SSL_get_fd(ssl), &readfds);

        // Ожидание событий на сокетах
        if (select(FD_SETSIZE, &readfds, NULL, NULL, NULL) < 0)
        {
            perror("select failed");
            exit(EXIT_FAILURE);
        }

        // Обработка незашифрованных соединений
        if (FD_ISSET(unencrypted_connfd, &readfds))
        {
           
                handleErrors("Failed to accept unencrypted connection");
            bytes_received = recv(unencrypted_connfd, buffer, sizeof(buffer), 0);
            if (bytes_received > 0)
            {
                printf("Received unencrypted data.\n");
                if (SSL_write(ssl, buffer, bytes_received) <= 0)
                    perror("Failed to write encrypted data");
            }
            else if (bytes_received == 0)
            {
                printf("Client closed connection\n");
                break;
            }
            else
            {
                perror("Error reading unencrypted data from client");
            }
        }

        // Обработка зашифрованных соединений
        if (FD_ISSET(SSL_get_fd(ssl), &readfds))
        {
            bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
            if (bytes_received > 0)
            {
                printf("Received encrypted data from server.\n");
                if (send(unencrypted_sockfd, buffer, bytes_received, 0) < 0)
                    perror("Failed to send decrypted data");
            }
            else if (bytes_received == 0)
            {
                printf("Server closed connection\n");
                break;
            }
            else
            {
                perror("Error reading encrypted data from server");
            }
        }
    }

    // Закрытие соединения и освобождение ресурсов
    close(unencrypted_sockfd);
    SSL_shutdown(ssl);
    SSL_free(ssl);

    free(sockets);
    pthread_exit(NULL);
}

int main()
{
    logEvent(INFO, "Application started");

    printf("запуск : \n");
    // Создание незашифрованного сокета и установка соединения с сервером
    setupUnencryptedSocket();
    printf(" клиент пришел: \n");

    // Установка зашифрованного соединения с сервером
    ssl = establishEncryptedConnection();
    printf("запуск  послушки: \n");

    // Подготовка аргументов для функции handle_connection
    int *sockets = malloc(2 * sizeof(int));
    if (sockets == NULL)
    {
        perror("Failed to allocate memory");
        exit(EXIT_FAILURE);
    }
    sockets[0] = unencrypted_connfd;
    sockets[1] = SSL_get_fd(ssl); // Получаем файловый дескриптор SSL сокета

    // Создание и запуск потока для обработки соединения
    pthread_t connectionThread;
    if (pthread_create(&connectionThread, NULL, handle_connection, (void *)sockets) != 0)
    {
        perror("Failed to create connection thread");
        exit(EXIT_FAILURE);
    }

    // Ожидание завершения потока
    pthread_join(connectionThread, NULL);

    // Закрытие соединения и освобождение ресурсов
    close(unencrypted_sockfd);
    SSL_shutdown(ssl);
    SSL_free(ssl);

    logEvent(INFO, "Application exiting");
    return 0;
}
