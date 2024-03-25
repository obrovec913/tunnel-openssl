#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
// #include <libconfig.h>
#include <openssl/crypto.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <signal.h>
#include <poll.h>
#include <fcntl.h>

#define PORT 12345
#define UNENCRYPTED_PORT 5412
#define MAX_BUFFER_SIZE 2024
#define CHUNK_SIZE 1024
#define CIPHER "DHE-BIGN-WITH-BELT-DWP-HBELT"
#define PSK_KEY "123456"
#define PSK_HINT "123"
#define SERVER_KEY_FILE "./keys/bign-curve256v1.key" // Путь к файлу с закрытым ключом сервера
#define SERVER_CERT_FILE "./keys/cert.pem"           // Путь к файлу с сертификатом сервера

// Структура для передачи параметров в поток обработки SSL-соединения
typedef struct
{
    int sockfd; // Идентификатор сокета
    SSL *ssl;   //  SSL
    int encrypt;
    pthread_t receiveThread;
    pthread_t sendThread;
    //    pthread_t prosseThread;
} SSLThreadData;

pthread_t prosseThread;
int unencrypted_sockfd;
int sockfds;
int unencrypted_con;
int connected, cl = 0;
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
typedef struct
{
    char *ip_address;
    int unencrypted_port;
    int encrypted_port;
    char *private_key;
    char *certificate;
    char *psk_key;
    char *psk_hint;
    char *ciphers;
} ConfigParams;
/*
void readConfig(const char *filename, ConfigParams *params)
{
    config_t cfg;

    // Инициализация конфигурации
    config_init(&cfg);

    // Загрузка конфигурационного файла
    if (!config_read_file(&cfg, filename))
    {
        fprintf(stderr, "Error reading config file.\n");
        config_destroy(&cfg);
        exit(1);
    }

    // Получение параметров из конфига
    config_lookup_string(&cfg, "server.ip_address", &params->ip_address);
    config_lookup_int(&cfg, "server.unencrypted_port", &params->unencrypted_port);
    config_lookup_int(&cfg, "server.encrypted_port", &params->encrypted_port);
    config_lookup_string(&cfg, "server.private_key", &params->private_key);
    config_lookup_string(&cfg, "server.certificate", &params->certificate);
    config_lookup_string(&cfg, "server.psk_key", &params->psk_key);
    config_lookup_string(&cfg, "server.psk_hint", &params->psk_hint);
    config_lookup_string(&cfg, "server.ciphers", &params->ciphers);

    // Освобождение ресурсов
    config_destroy(&cfg);
}
*/
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
void info_callback(const SSL *ssl, int where, int ret)
{
    const char *str;
    int w;

    w = where & ~SSL_ST_MASK;

    if (w & SSL_ST_CONNECT)
    {
        str = "SSL_connect";
    }
    else if (w & SSL_ST_ACCEPT)
    {
        str = "SSL_accept";
    }
    else
    {
        str = "undefined";
    }

    if (where & SSL_CB_LOOP)
    {
        printf("%s:%s\n", str, SSL_state_string_long(ssl));
    }
    else if (where & SSL_CB_ALERT)
    {
        str = (where & SSL_CB_READ) ? "read" : "write";
        printf("SSL3 alert %s:%s:%s\n", str, SSL_alert_type_string_long(ret), SSL_alert_desc_string_long(ret));
    }
    else if (where & SSL_CB_EXIT)
    {
        if (ret == 0)
        {
            printf("%s:failed in %s\n", str, SSL_state_string_long(ssl));
        }
        else if (ret < 0)
        {
            printf("%s:error in %s\n", str, SSL_state_string_long(ssl));
        }
    }
}

void ssl_msg_callback(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg)
{
    const char *msg_type;
    // printf("\n");
    switch (content_type)
    {
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

int setSocketNonBlocking(int sockfd)
{
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1)
    {
        perror("fcntl F_GETFL failed");
        return -1;
    }
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        perror("fcntl F_SETFL failed");
        return -1;
    }
    return 0;
}

int connectToServer(const char *server_ip, int server_port)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("socket creation failed");
        return -1;
    }
    if (setSocketNonBlocking(sockfd) < 0)
    {
        close(sockfd);
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(server_ip);
    server_addr.sin_port = htons(server_port);

    int connect_status = connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (connect_status < 0)
    {
        if (errno == EINPROGRESS)
        {
            // Соединение еще не установлено, ожидаем его завершения
            fd_set write_fds;
            FD_ZERO(&write_fds);
            FD_SET(sockfd, &write_fds);
            struct timeval timeout;
            timeout.tv_sec = 10; // Установите желаемый тайм-аут в секундах
            timeout.tv_usec = 0;
            int select_status = select(sockfd + 1, NULL, &write_fds, NULL, &timeout);
            if (select_status < 0)
            {
                perror("select failed");
                close(sockfd);
                return -1;
            }
            else if (select_status == 0)
            {
                // Тайм-аут select
                printf("Connection timed out\n");
                close(sockfd);
                return -1;
            }
            else
            {
                // Соединение установлено успешно
                printf("Connected to the server\n");
            }
        }
        else
        {
            // Ошибка при подключении
            perror("connect failed");
            close(sockfd);
            return -1;
        }
    }
    else
    {
        // Соединение установлено сразу
        printf("Connected to the server\n");
    }

    return sockfd;
}

SSL *establishSSLConnection(int sockfd, SSL_CTX *ctx)
{
    SSL *ssl = SSL_new(ctx);
    if (!ssl)
    {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    if (SSL_set_fd(ssl, sockfd) != 1)
    {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }

    // Попытка установки SSL соединения
    int ssl_connect_status = SSL_connect(ssl);
    if (ssl_connect_status != 1)
    {
        int ssl_error = SSL_get_error(ssl, ssl_connect_status);
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
        {
            // SSL_connect требует дальнейших операций ввода/вывода для завершения подключения
            printf("SSL_connect in progress\n");
            // Обработка неблокирующего подключения к SSL сокету
        }
        else
        {
            // Ошибка при SSL подключении
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            return NULL;
        }
    }
    else
    {
        // SSL соединение установлено успешно
        printf("SSL connection established\n");
    }

    return ssl;
}

void setupUnencryptedSocket(int port, char *ipad)
{
    logEvent(INFO, "Setting up unencrypted socket");
    struct sockaddr_in unencrypted_serv_addr;

    if ((unencrypted_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        handleErrors("Failed to create unencrypted socket");

    // Установка сокета в неблокирующий режим
    if (fcntl(unencrypted_sockfd, F_SETFL, O_NONBLOCK) < 0)
    {
        handleErrors("Failed to set socket to non-blocking mode");
    }
    // Опция для повторного использования адреса
    int enable = 1;
    if (setsockopt(unencrypted_sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
        handleErrors("Failed to set socket option for unencrypted socket");

    memset(&unencrypted_serv_addr, 0, sizeof(unencrypted_serv_addr));
    unencrypted_serv_addr.sin_family = AF_INET;
    unencrypted_serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    unencrypted_serv_addr.sin_port = htons(port);

    if (bind(unencrypted_sockfd, (struct sockaddr *)&unencrypted_serv_addr, sizeof(unencrypted_serv_addr)) < 0)
        handleErrors("Failed to bind unencrypted socket");

    if (listen(unencrypted_sockfd, 1) < 0)
        handleErrors("Failed to listen on unencrypted socket");
}

SSL *createSSLConnection(int sockfd, SSL_CTX *ssl_ctx)
{
    SSL *ssl = SSL_new(ssl_ctx);
    if (!ssl)
    {
        handleErrors("Failed to create new SSL connection");
    }
    if (SSL_set_fd(ssl, sockfd) != 1)
    {
        handleErrors("Failed to set file descriptor for SSL connection");
    }
    if (SSL_accept(ssl) != 1)
    {
        handleErrors("Failed to accept SSL connection");
    }
    return ssl;
}

// Функция, выполняемая в отдельном потоке для проверки разрыва соединения

void *receiveThreadFunction(void *arg)
{
    SSLThreadData *data = (SSLThreadData *)arg;
    printf("Receive thread started\n");
    char buffer[MAX_BUFFER_SIZE];
    int bytes_received;
    int flags = 0;
    int err;
    int ssl_fd = SSL_get_fd(data->ssl);
    fd_set fds;
    struct timeval timeout;

    while (1)
    {
        FD_ZERO(&fds);
        FD_SET(ssl_fd, &fds);
        timeout.tv_sec = 10; // Установите желаемый тайм-аут в секундах
        timeout.tv_usec = 0;

        int ret = select(ssl_fd + 1, &fds, NULL, NULL, &timeout);
        if (ret == -1)
        {
            perror("Error in select");
            break;
        }
        else if (ret == 0)
        {
            if (flags >= 20)
            {
                break;
            }
            flags++;
            printf("Timeout in receive thread\n");
            continue;
        }

        // Принятие зашифрованных данных от сервера
        bytes_received = SSL_read(data->ssl, buffer, sizeof(buffer));

        if (bytes_received > 0)
        {
            printf("Received encrypted data from server\n");
            flags = 0;

            // Отправка данных по незашифрованному сокету
            int sent = send(data->sockfd, buffer, bytes_received, 0);
            if (sent < 0)
            {
                perror("Failed to send decrypted data");
                break;
            }

            memset(buffer, 0, sizeof(buffer)); // Очистка буфера
        }
        else
        {
            err = SSL_get_error(data->ssl, bytes_received);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            {
                // Нет данных доступных на чтение/запись, продолжаем ожидание

                continue;
            }
            else
            {
                // Произошла ошибка при чтении данных
                perror("Failed to read encrypted data");
                break;
            }
        }
    }
    free(data);

    printf("Receive thread exiting\n");
    pthread_exit(NULL);
}

void *sendThreadFunction(void *arg)
{
    SSLThreadData *data = (SSLThreadData *)arg;
    printf("Send thread started\n");
    char buffer[MAX_BUFFER_SIZE];
    int bytes_received;
    int flags = 0;
    fd_set fds;
    struct timeval timeout;

    while (1)
    {
        FD_ZERO(&fds);
        FD_SET(data->sockfd, &fds);
        timeout.tv_sec = 10; // Установите желаемый тайм-аут в секундах
        timeout.tv_usec = 0;

        int ret = select(data->sockfd + 1, &fds, NULL, NULL, &timeout);
        if (ret == -1)
        {
            perror("Error in select");
            break;
        }
        else if (ret == 0)
        {
            printf("Timeout in send thread\n");
            if (flags >= 20)
            {
                break;
            }
            flags++;
            continue;
        }

        // Принятие незашифрованных данных от клиента
        bytes_received = recv(data->sockfd, buffer, sizeof(buffer), 0);

        if (bytes_received > 0)
        {
            printf("Received unencrypted data\n");
            flags = 0;

            // Отправка данных по SSL соединению
            int sent = SSL_write(data->ssl, buffer, bytes_received);
            if (sent <= 0)
            {
                perror("Failed to write encrypted data");
                break;
            }

            memset(buffer, 0, sizeof(buffer)); // Очистка буфера
        }
        else
        {
            if (errno == EWOULDBLOCK || errno == EAGAIN)
            {
                // Нет данных доступных на чтение, продолжаем ожидание

                continue;
            }
            else
            {
                // Произошла ошибка при чтении данных
                perror("Failed to read unencrypted data");
                break;
            }
        }
    }
    free(data);

    printf("Send thread exiting\n");
    pthread_exit(NULL);
}
void *prosseThreadFunction(void *arg)
{
    SSLThreadData *data = (SSLThreadData *)arg;
    logEvent(INFO, "pros thread started");
    if (pthread_create(&data->sendThread, NULL, sendThreadFunction, data) != 0)
    {
        handleErrors("Failed to create send thread");
    }
    // Создание и запуск потока для чтения данных от сервера
    if (pthread_create(&data->receiveThread, NULL, receiveThreadFunction, data) != 0)
    {
        handleErrors("Failed to create receive thread");
    }

    pthread_join(data->sendThread, NULL);
    pthread_join(data->receiveThread, NULL);
   // SSL_shutdown(data->ssl);
    //SSL_free(data->ssl);
    close(data->sockfd);
    close(data->encrypt);
    //    connected = 0;
    printf("Received prosse.\n");
    free(data);

    logEvent(INFO, "Receive thread exiting");
    pthread_exit(NULL);
}

void *listenThreadFunctionss(void *arg)
{
    logEvent(INFO, "Listen thread started");
    // SSL_CTX *ssl_ctx;
    // int u_con;
    SSLThreadData *data = malloc(sizeof(SSLThreadData));
    if (!data)
    {
        handleErrors("Failed to allocate memory for connection fd");
    }
    // SSL *ssl;
    while (1)
    {

        if (reg == 1)
        {

            int ssl_connfd = accept(unencrypted_sockfd, NULL, NULL);
            if (ssl_connfd < 0)
            {
                if (errno == EWOULDBLOCK || errno == EAGAIN)
                {
                    //       printf("слушаем ssl порт.\n");
                    // Нет новых соединений в данный момент
                    continue;
                }
                else
                {
                    perror("Failed to accept connection");
                }
            }
            // Обработка нового подключения
            logEvent(INFO, " new ssl connection.\n");
            // Можно добавить здесь логику для обработки нового подключения
            SSL_CTX *ssl_ctx = createSSLContext();
            int sock = connectToServer(logip, uport);
            if (sock < 0)
            {
                SSL_CTX_free(ssl_ctx);
                break;
            }
            SSL *ssl = createSSLConnection(ssl_connfd, ssl_ctx);
            data->sockfd = sock;
            data->ssl = ssl;
            data->encrypt = ssl_connfd;
        }
        else if (reg == 2)
        {
            int u_cone = accept(unencrypted_sockfd, NULL, NULL);
            if (u_cone < 0)
            {

                if (errno == EWOULDBLOCK || errno == EAGAIN)
                {
                    // Нет новых соединений в данный момент
                    continue;
                }
                else
                {
                    perror("Failed to accept connection");
                }
            }
            // Обработка нового подключения
            logEvent(INFO, "Accepted new unencrypted connection.\n");
            SSL_CTX *ctx = createSSLContextcl();
            int sockfd = connectToServer(ip, eport);
            if (sockfd < 0)
            {
                SSL_CTX_free(ctx);
                break;
            }

            SSL *ssl = establishSSLConnection(sockfd, ctx);
            if (!ssl)
            {
                close(sockfd);
                SSL_CTX_free(ctx);
                break;
            }

            //  SSL *ssl = establishEncryptedConnectionCl();

            data->sockfd = u_cone;
            data->ssl = ssl;
        }

        // Создание и запуск потока для отправки данных серверу

        if (pthread_create(&prosseThread, NULL, prosseThreadFunction, data) != 0)
        {
            handleErrors("Failed to create send thread");
        }
        // free(data);
    }
    logEvent(INFO, "Listen thread exiting");
    // Ожидание завершения потоков
    pthread_join(prosseThread, NULL);

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
        setupUnencryptedSocket(eport, ip);
        pthread_t listenThread;
        if (pthread_create(&listenThread, NULL, listenThreadFunctionss, NULL) != 0)
        {
            fprintf(stderr, "Failed to create listen thread.\n");
            handleErrors("Failed to create listen thread");
        }

        pthread_join(listenThread, NULL);

        // pthread_join(listenThread, NULL);
        // close(unencrypted_con);
    }
    else if (reg == 2)
    {
        if (ip == NULL)
        {
            handleErrors("error not ip server");
        }
        printf("Initializing unencrypted socket...\n");
        setupUnencryptedSocket(uport, logip);
        pthread_t listenThread;
        if (pthread_create(&listenThread, NULL, listenThreadFunctionss, NULL) != 0)
        {
            fprintf(stderr, "Failed to create listen thread.\n");
            handleErrors("Failed to create listen thread");
        }

        pthread_join(listenThread, NULL);
    }

    // Закрытие соединения и освобождение ресурсов
    close(unencrypted_sockfd);
    //   SSL_shutdown(ssl);
    // SSL_free(ssl);
    logEvent(INFO, "Application exiting");
    return 0;
}