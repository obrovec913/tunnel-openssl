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
#include <sys/stat.h>
#include <signal.h>

#define PORT 12345
#define UNENCRYPTED_PORT 5412
#define MAX_BUFFER_SIZE 2024
#define CHUNK_SIZE 1024
#define CIPHER "DHE-BIGN-WITH-BELT-DWP-HBELT"
#define PSK_KEY "123456"
#define PSK_HINT "123"
#define SERVER_KEY_FILE "./keys/bign-curve256v1.key" // Путь к файлу с закрытым ключом сервера
#define SERVER_CERT_FILE "./keys/cert.pem"           // Путь к файлу с сертификатом сервера

// Флаг для отслеживания разрыва соединения
volatile sig_atomic_t connection_lost = 0;

pthread_t receiveThread, sendThread;
int unencrypted_sockfd;
SSL *ssl;
int unencrypted_con;
SSL_CTX *ssl_ctx;
int connected, cl = 0;
int *global_connfd_ptr;
int uport, eport, reg = 0;
char *logip, *ip, *ciphers, *certS, *pkey, *psk_k, *psk_i = NULL;
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
    strncpy((char *)identity, psk_i, max_psk_len - 1);
    // identity[max_psk_len - 1] = '\0'; // Убедимся, что строка завершается нулевым символом
    strncpy((char *)psk, psk_k, max_psk_len);
    return strlen(psk_k);
}

int psk_client_callback(SSL *ssl, const char *hint, char *identity, unsigned int max_identity_len, unsigned char *psk, unsigned int max_psk_len)
{
    strncpy((char *)psk, psk_k, max_psk_len);
    return strlen(psk_k);
}

// Callback функция для обработки информационных сообщений SSL
void info_callback(const SSL *ssl, int where, int ret) {
    const char *str;
    int w;

    w = where & ~SSL_ST_MASK;

    if (w & SSL_ST_CONNECT) {
        str = "SSL_connect";
    } else if (w & SSL_ST_ACCEPT) {
        str = "SSL_accept";
    } else {
        str = "undefined";
    }

    if (where & SSL_CB_LOOP) {
        printf("%s:%s\n", str, SSL_state_string_long(ssl));
    } else if (where & SSL_CB_ALERT) {
        str = (where & SSL_CB_READ) ? "read" : "write";
        printf("SSL3 alert %s:%s:%s\n", str, SSL_alert_type_string_long(ret), SSL_alert_desc_string_long(ret));
    } else if (where & SSL_CB_EXIT) {
        if (ret == 0) {
            printf("%s:failed in %s\n", str, SSL_state_string_long(ssl));
        } else if (ret < 0) {
            printf("%s:error in %s\n", str, SSL_state_string_long(ssl));
        }
    }
}



void ssl_msg_callback(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg) {
    const char *msg_type;
    const char *msg_type = write_p ? "Sent" : "Received";
    printf("[SSL] %s %zu bytes: ", msg_type, len);

    // Вывод содержимого буфера в шестнадцатеричном виде
    const unsigned char *data = (const unsigned char *)buf;
    for (size_t i = 0; i < len; ++i) {
        printf("%02X ", data[i]);
    }
    printf("\n");
    switch (content_type) {
        case SSL3_RT_CHANGE_CIPHER_SPEC:
            msg_type = "ChangeCipherSpec";
            break;
        case SSL3_RT_ALERT:
            msg_type = "Alert";
            break;
        case SSL3_RT_HANDSHAKE:
            msg_type = "Handshake";
            break;
        case SSL3_RT_APPLICATION_DATA:
            msg_type = "ApplicationData";
            break;
        case SSL3_RT_HEARTBEAT:
            msg_type = "Heartbeat";
            break;
        default:
            msg_type = "Unknown";
            break;
    }

    printf("SSL message received: type=%s, length=%zu\n", msg_type, len);
}


SSL_CTX *createSSLContextcl()
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

    // Загрузка PSK
    SSL_CTX_set_psk_client_callback(ctx, psk_client_callback);
    SSL_CTX_set_msg_callback(ctx, ssl_msg_callback);

    return ctx;
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
    SSL_CTX_set_msg_callback(ctx, ssl_msg_callback);

    // Установка параметров алгоритмов шифрования
    if (SSL_CTX_set_cipher_list(ctx, ciphers) != 1)
    {
        handleErrors("Failed to load Cipher");
    }

    SSL_CTX_set_psk_server_callback(ctx, psk_server_callback);

    // Загрузка сертификата и ключа сервера
    logEvent(INFO, "Loading server certificate and key");
    if (SSL_CTX_use_certificate_file(ctx, certS, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, pkey, SSL_FILETYPE_PEM) != 1)
        handleErrors("Failed to load server certificate or key");

    return ctx;
}

SSL *establishEncryptedConnectionCl()
{
    logEvent(INFO, "Establishing encrypted connection");
    SSL_CTX *ssl_ctx = createSSLContextcl();
    SSL *ssl;

    int encrypted_sockfd;
    struct sockaddr_in encrypted_serv_addr;

    if ((encrypted_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        handleErrors("Failed to create socket for encrypted connection");

    memset(&encrypted_serv_addr, 0, sizeof(encrypted_serv_addr));
    encrypted_serv_addr.sin_family = AF_INET;
    encrypted_serv_addr.sin_port = htons(eport);
    encrypted_serv_addr.sin_addr.s_addr = inet_addr(ip); // Замените на IP вашего сервера

    if (connect(encrypted_sockfd, (struct sockaddr *)&encrypted_serv_addr, sizeof(encrypted_serv_addr)) < 0)
        handleErrors("Failed to connect to encrypted port");

    ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, encrypted_sockfd);

    if (SSL_connect(ssl) != 1)
        handleErrors("Failed to establish SSL connection");

    printf("подключился : \n");

    return ssl;
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
    unencrypted_serv_addr.sin_addr.s_addr = inet_addr(logip);
    unencrypted_serv_addr.sin_port = htons(uport);

    if (bind(unencrypted_sockfd, (struct sockaddr *)&unencrypted_serv_addr, sizeof(unencrypted_serv_addr)) < 0)
        handleErrors("Failed to bind unencrypted socket");

    if (listen(unencrypted_sockfd, 1) < 0)
        handleErrors("Failed to listen on unencrypted socket");
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
    server_addr.sin_port = htons(eport);
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
    // SSL_CTX_free(ssl_ctx);

    return ssl;
}
int connectToUnencryptedPort()
{
    // Создание сокета
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("Ошибка при создании сокета");
        return -1;
    }

    // Заполнение структуры sockaddr_in для сервера
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(uport);
    server_addr.sin_addr.s_addr = inet_addr(logip);

    // Подключение к серверу
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        handleErrors("Ошибка при подключении к серверу");
        close(sockfd);
        return -1;
    }

    return sockfd; // Возвращаем файловый дескриптор подключенного сокета
}

// Функция, выполняемая в отдельном потоке для проверки разрыва соединения
void *check_connection(void *arg)
{
    while (1)
    {
        if (connection_lost)
        {
            printf("Connection lost!\n");
            // Здесь можно добавить логику для переподключения или других действий
            // Сбрасываем флаг после обработки разрыва соединения
            connection_lost = 0;
        }
        sleep(1); // Проверка раз в секунду
    }
    return NULL;
}

void *receiveThreadFunction(void *arg)
{
    logEvent(INFO, "Receive thread started");
    char buffer[MAX_BUFFER_SIZE];
    int bytes_received;

    while (1)
    {
        // Принятие зашифрованных данных от сервера
        bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes_received > 0)
        {
            logEvent(INFO, "Received encrypted data from server");
            // printf("Received encrypted data from server.\n");

            if (global_connfd_ptr != NULL)
            {
                int unencrypted_connfd = *global_connfd_ptr;
                // Теперь мы можем использовать unencrypted_connfd для чтения или записи данных

                printf("\n");
                if (send(unencrypted_connfd, buffer, bytes_received, 0) < 0)
                {
                    handleErrors("Failed to send decrypted data");
                }
            }
            // Очистка буфера
            memset(buffer, 0, sizeof(buffer));
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
        if (global_connfd_ptr != NULL)
        {
            int unencrypted_connfd = *global_connfd_ptr;
            // Принятие зашифрованных данных от сервера
            bytes_received = recv(unencrypted_connfd, buffer, sizeof(buffer), 0);
        }
        if (bytes_received > 0)
        {
            logEvent(INFO, "Received unencrypted data ");
            // printf("Received unencrypted data.\n");
            if (SSL_write(ssl, buffer, bytes_received) <= 0)
            {
                handleErrors("Failed to write encrypted data");
            }
            // Очистка буфера
            memset(buffer, 0, sizeof(buffer));
        }
    }

    logEvent(INFO, "Send thread exiting");
    pthread_exit(NULL);
}
void *listenThreadFunction(void *arg)
{
    logEvent(INFO, "Listen thread started");
    pthread_t thread;
    while (1)
    {
        int unencrypted_connfd = accept(unencrypted_sockfd, NULL, NULL);
        if (unencrypted_connfd < 0)
        {
            handleErrors("Failed to accept unencrypted connection");
        }
        // Обработка нового подключения
        printf("Accepted new unencrypted connection.\n");
        // Можно добавить здесь логику для обработки нового подключения
        if (cl == 1)
        {
            printf("Establishing encrypted connection... \n");
            ssl = establishEncryptedConnectionCl();

            if (pthread_create(&thread, NULL, check_connection, NULL) != 0)
            {
                fprintf(stderr, "Failed to create thread.\n");
            }

            // Создание и запуск потока для отправки данных серверу
            if (pthread_create(&sendThread, NULL, sendThreadFunction, NULL) != 0)
            {
                fprintf(stderr, "Failed to create send thread.\n");
                handleErrors("Failed to create send thread");
            }

            // Создание и запуск потока для чтения данных от сервера
            if (pthread_create(&receiveThread, NULL, receiveThreadFunction, NULL) != 0)
            {
                fprintf(stderr, "Failed to create receive thread.\n");
                handleErrors("Failed to create receive thread");
            }
            cl = 0;
        }

        int *connfd_ptr = malloc(sizeof(int));
        if (connfd_ptr == NULL)
        {
            handleErrors("Failed to allocate memory for connection fd");
        }
        *connfd_ptr = unencrypted_connfd;
        global_connfd_ptr = connfd_ptr;
    }
    logEvent(INFO, "Listen thread exiting");
    // Ожидание завершения потоков
    pthread_join(thread, NULL);
    pthread_join(sendThread, NULL);
    pthread_join(receiveThread, NULL);
    pthread_exit(NULL);
}

void *receiveThreadFunctions(void *arg)
{
    logEvent(INFO, "Receive thread started");
    char buffer[MAX_BUFFER_SIZE];
    int bytes_received;

    while (1)
    {
        // Принятие зашифрованных данных от сервера
        bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes_received > 0)
        {
            logEvent(INFO, "Received encrypted data from server");
            // printf("Received encrypted data from server.\n");

            // Теперь мы можем использовать unencrypted_connfd для чтения или записи данных

            // printf("\n");
            if (send(unencrypted_con, buffer, bytes_received, 0) < 0)
            {
                handleErrors("Failed to send decrypted data");
            }

            // Очистка буфера
            memset(buffer, 0, sizeof(buffer));
        }
    }

    logEvent(INFO, "Receive thread exiting");
    pthread_exit(NULL);
}

void *sendThreadFunctions(void *arg)
{
    logEvent(INFO, "Send thread started");
    char buffer[MAX_BUFFER_SIZE];
    int bytes_received;

    while (1)
    {
        // Принятие зашифрованных данных от сервера
        bytes_received = recv(unencrypted_con, buffer, sizeof(buffer), 0);

        if (bytes_received > 0)
        {
            logEvent(INFO, "Received unencrypted data ");
            // printf("Received unencrypted data.\n");
            if (SSL_write(ssl, buffer, bytes_received) <= 0)
            {
                handleErrors("Failed to write encrypted data");
            }
            // Очистка буфера
            memset(buffer, 0, sizeof(buffer));
        }
    }

    logEvent(INFO, "Send thread exiting");
    pthread_exit(NULL);
}

int main(int argc, char *argv[])
{
    int opt;

    logEvent(INFO, "Application started");
    while ((opt = getopt(argc, argv, "d:u:e:y:r:k:p:i:h:c:s:")) != -1)
    {
        switch (opt)
        {
        case 'd':
            logip = optarg;
            break;
        case 'u':
            uport = atoi(optarg);
            break;
        case 'e':
            eport = atoi(optarg);
            break;
        case 'y':
            pkey = optarg;
            break;
        case 'r':
            certS = optarg;
            break;
        case 'k':
            psk_k = optarg;
            break;
        case 'p':
            psk_i = optarg;
            break;
        case 'i':
            ip = optarg;
            break;
        case 'h':
            ciphers = optarg;
            break;
        case 'c':
            cl = atoi(optarg);
            reg = 2;
            break;
        case 's':
            reg = 1;
            break;
        default:
            fprintf(stderr, "Usage: %s -u <uport> -e <eport> -y <riv-key> -c <path server-cert> -k <psk_k> -p <psk_i>\n", argv[0]);
            break;
        }
    }
    if (uport == 0)
    {
        uport = UNENCRYPTED_PORT;
    }
    if (eport == 0)
    {
        eport = PORT;
        /* code */
    }
    if (pkey == NULL)
    {
        pkey = SERVER_KEY_FILE;
        /* code */
    }
    if (certS == NULL)
    {
        certS = SERVER_CERT_FILE;
        /* code */
    }
    if (psk_k == NULL)
    {
        psk_k = PSK_KEY;
        /* code */
    }
    if (psk_i == NULL)
    {
        psk_i = PSK_HINT;
    }
    if (ciphers == NULL)
    {
        ciphers = CIPHER;
        /* code */
    }
    if (logip == NULL)
    {
        handleErrors("error not ip local");
    }
    if (reg == 0)
    {
        handleErrors("error reg");
        /* code */
    }
    else if (reg == 1)
    {

        printf("Establishing encrypted connection...\n");
        ssl = establishEncryptedConnection();
        unencrypted_con = connectToUnencryptedPort();
        pthread_t thread;
        if (pthread_create(&thread, NULL, check_connection, NULL) != 0)
        {
            fprintf(stderr, "Failed to create thread.\n");
            return EXIT_FAILURE;
        }

        // Создание и запуск потока для отправки данных серверу
        if (pthread_create(&sendThread, NULL, sendThreadFunctions, NULL) != 0)
        {
            fprintf(stderr, "Failed to create send thread.\n");
            handleErrors("Failed to create send thread");
        }

        // Создание и запуск потока для чтения данных от сервера
        if (pthread_create(&receiveThread, NULL, receiveThreadFunctions, NULL) != 0)
        {
            fprintf(stderr, "Failed to create receive thread.\n");
            handleErrors("Failed to create receive thread");
        }
        // pthread_join(listenThread, NULL);
        pthread_join(thread, NULL);
        pthread_join(sendThread, NULL);
        pthread_join(receiveThread, NULL);
        close(unencrypted_con);
    }
    else if (reg == 2)
    {
        if (ip == NULL)
        {
            handleErrors("error not ip server");
        }
        printf("Initializing unencrypted socket...\n");
        setupUnencryptedSocket();
        pthread_t listenThread;
        if (pthread_create(&listenThread, NULL, listenThreadFunction, NULL) != 0)
        {
            fprintf(stderr, "Failed to create listen thread.\n");
            handleErrors("Failed to create listen thread");
        }

        pthread_join(listenThread, NULL);
    }

    // Закрытие соединения и освобождение ресурсов
    close(unencrypted_sockfd);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    logEvent(INFO, "Application exiting");
    return 0;
}