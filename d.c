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
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#define PORT 12345
#define UNENCRYPTED_PORT 5412
#define MAX_BUFFER_SIZE 2024
#define CHUNK_SIZE 1024

pthread_t receiveThread, sendThread;
int unencrypted_sockfd;
SSL *ssl;
SSL_CTX *ssl_ctx;
int connected = 0;

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
    if ((ctx = SSL_CTX_new(SSLv23_server_method())) == NULL)
        handleErrors("Failed to create SSL context");

    // Загрузка корневого сертификата
    logEvent(INFO, "Loading root certificate");
    if (SSL_CTX_load_verify_locations(ctx, "./keys/root_cert.pem", NULL) != 1)
        handleErrors("Failed to load root certificate");

    // Загрузка сертификата и ключа сервера
    logEvent(INFO, "Loading server certificate and key");
    if (SSL_CTX_use_certificate_file(ctx, "./keys/server_cert.pem", SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, "./keys/server_key.pem", SSL_FILETYPE_PEM) != 1)
        handleErrors("Failed to load server certificate or key");

    // Проверка правильности ключа
    logEvent(INFO, "Checking server private key");
    if (SSL_CTX_check_private_key(ctx) != 1)
        handleErrors("Server private key check failed");

    return ctx;
}

int setupUnencryptedSocket()
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
    
    int client_sockfd;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    if ((client_sockfd = accept(unencrypted_sockfd, (struct sockaddr *)&client_addr, &client_len)) < 0) {
        perror("Failed to accept connection on unencrypted socket");
        exit(EXIT_FAILURE);
    }
    return client_sockfd;
}

SSL *establishEncryptedConnection()
{
    logEvent(INFO, "Establishing encrypted connection");
    // Устанавливаем защищенное соединение
    SSL *ssl;
    SSL_CTX *ssl_ctx = createSSLContext();
      ENGINE *engine = ENGINE_by_id("bee2evp");
    if (!engine)
    {
        handleErrors("Failed to load bee2evp engine");
    }

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
    const char *cipher_list = "AES256-GCM-SHA384";
    //const char *cipher_list = "belt-ecb128";

    // Устанавливаем список шифров для SSL сокета
    if (SSL_set_cipher_list(ssl, cipher_list) != 1)
    {
        handleErrors("Failed to set cipher list");
    }

    // Освобождение контекста шифрования (не освобождаем ssl_ctx, так как он используется в основной функции)
    SSL_CTX_free(ssl_ctx);

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
    int unsecured_sockfd = connectUnencryptedPort();

    if (send(unsecured_sockfd, decrypted_data, decrypted_len, 0) < 0)
        handleErrors("Failed to send decrypted data");

    close(unsecured_sockfd);

    // pthread_exit(NULL);
    memset(decrypted_data, 0, sizeof(decrypted_data));
    EVP_CIPHER_CTX_free(ctx);
}

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

    printf("Encrypted WRITE ");
    memset(ciphertext, 0, sizeof(ciphertext));

    // Очистка контекста шифрования
    EVP_CIPHER_CTX_free(ctx);
}

int setNonBlocking(int sockfd)
{
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1)
    {
        return -1;
    }
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        return -1;
    }
    return 0;
}

// Функция мультиплексирования ввода-вывода
void multiplexIO(int unencrypted_sockfd, SSL *ssl)
{
    fd_set readfds;
    int max_fd;

    // Инициализация набора файловых дескрипторов
    FD_ZERO(&readfds);
    FD_SET(unencrypted_sockfd, &readfds);
    max_fd = unencrypted_sockfd;

    // Добавляем SSL сокет в набор
    int ssl_fd = SSL_get_fd(ssl);
    FD_SET(ssl_fd, &readfds);
    if (ssl_fd > max_fd)
    {
        max_fd = ssl_fd;
    }

    // Ожидание событий ввода-вывода
    if (select(max_fd + 1, &readfds, NULL, NULL, NULL) == -1)
    {
        handleErrors("Failed to perform IO multiplexing");
    }

    // Проверка событий на сокете для незашифрованных данных
    if (FD_ISSET(unencrypted_sockfd, &readfds))
    {
        // Принимаем данные на незашифрованном сокете
        char buffer[MAX_BUFFER_SIZE];
        int bytes_received = recv(unencrypted_sockfd, buffer, sizeof(buffer), 0);
        if (bytes_received > 0)
        {
            // Отправляем данные на зашифрованный сокет
            if (SSL_write(ssl, buffer, bytes_received) <= 0)
            {
                handleErrors("Failed to write data to SSL socket");
            }
        }
        else if (bytes_received == 0)
        {
            // Соединение закрыто
            close(unencrypted_sockfd);
            setupUnencryptedSocket();
            setNonBlocking(unencrypted_sockfd);

            // Дополнительная обработка, если необходимо
        }
        else
        {
            // Ошибка при чтении данных
            handleErrors("Failed to receive data from unencrypted socket");
        }
    }
    // Проверка событий на SSL сокете для зашифрованных данных
    if (FD_ISSET(ssl_fd, &readfds))
    {
        // Принимаем данные на SSL сокете
        char buffer[MAX_BUFFER_SIZE];
        int bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes_received > 0)
        {
            printf("Received encrypted data from server.\n");
            for (int i = 0; i < bytes_received; i++)
            {
                printf("%02x ", buffer[i]);
            }
            printf("\n");

            // Отправляем данные на незашифрованный сокет
            if (send(unencrypted_sockfd, buffer, bytes_received, 0) < 0)
            {
                handleErrors("Failed to send data to unencrypted socket");
            }
        }
        else if (bytes_received == 0)
        {
            // SSL соединение закрыто
            SSL_shutdown(ssl);
            SSL_free(ssl);
            ssl = establishEncryptedConnection();
            setNonBlocking(SSL_get_fd(ssl));
        }
        else
        {
            // Ошибка при чтении данных
            int err = SSL_get_error(ssl, bytes_received);
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
            {
                handleErrors("SSL read error");
            }
        }
    }
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
    //    server_clok = 0;
    int unencrypted_client_sockfd = setupUnencryptedSocket();
    setNonBlocking(unencrypted_client_sockfd);

    ssl = establishEncryptedConnection();
    setNonBlocking(SSL_get_fd(ssl));

    while (1)
    {
        multiplexIO(unencrypted_client_sockfd, ssl);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(createSSLContext());

    logEvent(INFO, "Application exiting");
    return 0;
}
