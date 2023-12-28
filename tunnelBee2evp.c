#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/engine.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pthread.h>

// Функция создания SSL контекста
SSL_CTX *create_ssl_context()
{
     // Загрузка bee2evp engine
    ENGINE_load_bee2evp();

    // Получение метода SSL для bee2evp
    const SSL_METHOD *method = ENGINE_by_id("bee2evp");
    if (!method) {
        ssl_error("Error getting bee2evp SSL method");
    }

    SSL_CTX *ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        ssl_error("Error creating SSL context");
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_cipher_list(ctx, CIPHER_ALGORITHM);
    return ctx;

}

// Функция обработки ошибок SSL
void ssl_error(const char *msg)
{
    perror(msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

// Функция обработки соединения в отдельном потоке
void *handle_connection(void *data)
{
    int *sockets = (int *)data;
    int local_socket = sockets[0];
    int remote_socket = sockets[1];

    // Создание SSL структуры
    SSL *ssl = SSL_new(create_ssl_context());
    if (ssl == NULL)
    {
        ssl_error("Error creating SSL structure");
    }
    SSL_set_fd(ssl, local_socket);

    // Установка SSL соединения с удаленным сервером
    if (SSL_connect(ssl) <= 0)
    {
        ssl_error("Error connecting to remote server");
    }
    else
    {
        // Принятие клиентского подключения после успешной установки удаленного соединения
        char buffer[4096];
        int bytes;

        fd_set read_fds, write_fds;
        while (1)
        {
            FD_ZERO(&read_fds);
            FD_ZERO(&write_fds);
            FD_SET(local_socket, &read_fds);
            FD_SET(remote_socket, &read_fds);

            // Проверка наличия данных для чтения
            if (select(remote_socket + 1, &read_fds, NULL, NULL, NULL) > 0)
            {
                if (FD_ISSET(local_socket, &read_fds))
                {
                    // Чтение из локального сокета и запись в удаленный
                    bytes = SSL_read(ssl, buffer, sizeof(buffer));
                    if (bytes > 0)
                    {
                        write(remote_socket, buffer, bytes);
                    }
                    else
                    {
                        break; // Проблемы с чтением из локального сокета
                    }
                }

                if (FD_ISSET(remote_socket, &read_fds))
                {
                    // Чтение из удаленного сокета и запись в локальный
                    bytes = read(remote_socket, buffer, sizeof(buffer));
                    if (bytes > 0)
                    {
                        SSL_write(ssl, buffer, bytes);
                    }
                    else
                    {
                        break; // Проблемы с чтением из удаленного сокета
                    }
                }
            }
        }
    }

    // Закрытие соединений и освобождение ресурсов
    close(local_socket);
    close(remote_socket);
    SSL_shutdown(ssl);
    SSL_free(ssl);

    free(sockets);
    pthread_exit(NULL);
}

// Функция создания SSL туннеля
void create_ssl_tunnel(const char *local_port_str, const char *remote_host, const char *remote_port_str)
{
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    // Создание серверного сокета
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1)
    {
        perror("Error creating server socket");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(atoi(local_port_str));

    // Привязка серверного сокета к локальному порту
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        perror("Error binding server socket");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Ожидание подключений
    listen(server_socket, 1);
    printf("Listening on localhost:%s\n", local_port_str);

    while (1)
    {
        // Принятие подключения от клиента
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_socket == -1)
        {
            perror("Error accepting connection");
            close(server_socket);
            exit(EXIT_FAILURE);
        }

        printf("Accepted connection from %s\n", inet_ntoa(client_addr.sin_addr));

        // Выделение памяти для передачи параметров в поток
        int *sockets = (int *)malloc(2 * sizeof(int));
        sockets[0] = client_socket;

        // Создание удаленного сокета и соединение с удаленным сервером
        int remote_socket = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in remote_addr;

        remote_addr.sin_family = AF_INET;
        remote_addr.sin_addr.s_addr = inet_addr(remote_host);
        remote_addr.sin_port = htons(atoi(remote_port_str));

        if (connect(remote_socket, (struct sockaddr *)&remote_addr, sizeof(remote_addr)) == -1)
        {
            perror("Error connecting to remote server");
            close(client_socket);
            free(sockets);
            exit(EXIT_FAILURE);
        }

        sockets[1] = remote_socket;

        // Создание потока для обработки соединения
        pthread_t thread;
        if (pthread_create(&thread, NULL, handle_connection, (void *)sockets) != 0)
        {
            perror("Error creating thread");
            close(client_socket);
            close(remote_socket);
            free(sockets);
            exit(EXIT_FAILURE);
        }

        pthread_detach(thread);
    }

    // Закрытие серверного сокета (не достигнуто, так как цикл бесконечен)
    close(server_socket);
}

int main(int argc, char *argv[])
{
    // Проверка наличия нужного количества аргументов командной строки
    if (argc != 4)
    {
        fprintf(stderr, "Usage: %s -e|-d [-c <cypher>] [local_ip:]local_port remote_host:remote_port\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Инициализация библиотек OpenSSL и Bee2evp
    ENGINE_load_bee2evp();
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Запуск туннеля с параметрами командной строки
    create_ssl_tunnel(argv[1], argv[2], argv[3]);

    // Очистка ресурсов
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
