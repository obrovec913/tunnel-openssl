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

#define PORT 12345
#define UNENCRYPTED_PORT 5412
#define MAX_BUFFER_SIZE 2024
#define CHUNK_SIZE 1024

#define PSK_KEY "123456"
#define PSK_HINT "123"
#define SERVER_KEY_FILE "./keys/bign-curve256v1.key" // Путь к файлу с закрытым ключом сервера
#define SERVER_CERT_FILE "./keys/cert.pem"           // Путь к файлу с сертификатом сервера

pthread_t receiveThread, sendThread;
int unencrypted_sockfd;
SSL *ssl;
SSL_CTX *ssl_ctx;
int connected = 0;
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
    FILE *logfile = fopen("server.log", "a");
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

unsigned int psk_server_callback(SSL *ssl, const char *identity, unsigned char *psk, unsigned int max_psk_len)
{
    strncpy((char *)identity, PSK_HINT, max_psk_len - 1);
    // identity[max_psk_len - 1] = '\0'; // Убедимся, что строка завершается нулевым символом
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

    // Инициализация OpenSSL
    logEvent(INFO, "Initializing OpenSSL");
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Создание нового SSL_CTX
    logEvent(INFO, "Creating new SSL context");
    if (!(ctx = SSL_CTX_new(TLSv1_2_server_method())))
    {
        printf("Failed to create SSL context\n");
        handleErrors("Failed to create SSL context");
    }
    SSL_CTX_set_info_callback(ctx, info_callback);

    // Установка параметров алгоритмов шифрования
    //    if (SSL_CTX_set_cipher_list(ctx, "DHT-PSK-BIGN-WITH-BELT-CTR-MAC-HBELT") != 1){
    //      handleErrors("Failed to load Cipher");
    //}
    // Загрузка корневого сертификата
    logEvent(INFO, "Loading root certificate");
    // if (SSL_CTX_load_verify_locations(ctx, "./keys/root_cert.pem", NULL) != 1)
    //   handleErrors("Failed to load root certificate");
    SSL_CTX_set_psk_server_callback(ctx, psk_server_callback);

    // Загрузка сертификата и ключа сервера
    logEvent(INFO, "Loading server certificate and key");
    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT_FILE, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY_FILE, SSL_FILETYPE_PEM) != 1)
        handleErrors("Failed to load server certificate or key");

    // Проверка правильности ключа
    logEvent(INFO, "Checking server private key");
    // if (SSL_CTX_check_private_key(ctx) != 1)
    //   handleErrors("Server private key check failed");

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

    // int unencrypted_connfd = accept(unencrypted_sockfd, NULL, NULL);
    //   if (unencrypted_connfd < 0)
    //      handleErrors("Failed to accept unencrypted connection");
}

SSL *establishEncryptedConnection()
{
    logEvent(INFO, "Establishing encrypted connection");
    // Устанавливаем защищенное соединение
    SSL *ssl;
    SSL_CTX *ssl_ctx = createSSLContext();

    // Устанавливаем серверный сокет
    int sockfd, connfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t len;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        handleErrors("Failed to create socket for encrypted connection");

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        handleErrors("Failed to bind socket for encrypted connection");

    if (listen(sockfd, 5) < 0)
        handleErrors("Failed to listen on socket for encrypted connection");

    // бесконечный цикл для прослушивания порта
    printf("слушаем порт : \n");
    while (!connected)
    {
        logEvent(INFO, "Waiting for encrypted connection");
        len = sizeof(client_addr);
        connfd = accept(sockfd, (struct sockaddr *)&client_addr, &len);
        if (connfd < 0)
            handleErrors("Failed to accept encrypted connection");

        // Создание SSL структуры
        ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, connfd);

        // Устанавливаем SSL соединение
        if (SSL_accept(ssl) == 1)
        {
            logEvent(INFO, "Encrypted connection established");
            printf("got server\n");
            connected = 1;
        }
        else
        {
            handleErrors("Failed to establish encrypted connection");
        }
    }

    // Освобождение контекста шифрования (не освобождаем ssl_ctx, так как он используется в основной функции)
    SSL_CTX_free(ssl_ctx);

    return ssl;
}

void *handle_connection(void *data)
{
    printf("за: \n");
    int *sockets = (int *)data;
    int unencrypted_sockfd = sockets[0];
    SSL *ssl = (SSL *)(intptr_t)sockets[1];

    char buffer[MAX_BUFFER_SIZE];
    int bytes_received;
    printf("слушки: \n");

    while (1)
    {
        fd_set readfds;
        FD_ZERO(&readfds);
        printf("зiu--- \n");
        FD_SET(unencrypted_sockfd, &readfds);
        printf("запyh: \n");
        FD_SET(SSL_get_fd(ssl), &readfds);
        printf("начал  : \n");

        // Ожидание событий на сокетах
        if (select(unencrypted_sockfd + 1, &readfds, NULL, NULL, NULL) > 0)
        {
            printf("соб : \n");

            // Обработка незашифрованных соединений
            if (FD_ISSET(unencrypted_sockfd, &readfds))
            {
                int unencrypted_connfd = accept(unencrypted_sockfd, NULL, NULL);
                if (unencrypted_connfd < 0)
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

    // Установка зашифрованного соединения с сервером
    ssl = establishEncryptedConnection();

    printf("ожидание клиента : \n");
    // Создание незашифрованного сокета и установка соединения с сервером
    setupUnencryptedSocket();
    printf("начал работу : \n");

    // Подготовка аргументов для функции handle_connection
    int *sockets = malloc(2 * sizeof(int));
    if (sockets == NULL)
    {
        perror("Failed to allocate memory");
        exit(EXIT_FAILURE);
    }
    sockets[0] = unencrypted_sockfd;
    sockets[1] = SSL_get_fd(ssl); // Получаем файловый дескриптор SSL сокета
    printf("запуск  послушки: \n");
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
