#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_HOST "tapaz.py" // Замените на нужный хост
#define SERVER_PORT 443            // 
#define LOCAL_PORT 8443            // Локальный порт, к которому будет подключаться клиент
#define CIPHER_ALGORITHM "AES256-SHA" // Замените на нужный алгоритм шифрования

SSL_CTX *create_ssl_context() {
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL) {
        perror("Error creating SSL context");
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_cipher_list(ctx, CIPHER_ALGORITHM);
    return ctx;
}

void ssl_error(const char *msg) {
    perror(msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

void create_ssl_tunnel(SSL_CTX *ctx, int local_port) {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    // Создание TCP-сервера для локального хоста и порта
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("Error creating server socket");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(local_port);

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Error binding server socket");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    listen(server_socket, 1);
    printf("Listening on localhost:%d\n", local_port);

    while (1) {
        // Принятие входящего соединения от клиента
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_socket == -1) {
            perror("Error accepting connection");
            close(server_socket);
            exit(EXIT_FAILURE);
        }

        printf("Accepted connection from %s\n", inet_ntoa(client_addr.sin_addr));

        // Создание SSL-соединения
        SSL *ssl = SSL_new(ctx);
        if (ssl == NULL) {
            ssl_error("Error creating SSL structure");
        }
        SSL_set_fd(ssl, client_socket);

        if (SSL_accept(ssl) <= 0) {
            ssl_error("Error accepting SSL connection");
        }

        // Подключение к удаленному серверу
        int remote_socket = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in remote_addr;

        remote_addr.sin_family = AF_INET;
        remote_addr.sin_addr.s_addr = inet_addr(SERVER_HOST);
        remote_addr.sin_port = htons(SERVER_PORT);

        if (connect(remote_socket, (struct sockaddr*)&remote_addr, sizeof(remote_addr)) == -1) {
            perror("Error connecting to remote server");
            close(client_socket);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            exit(EXIT_FAILURE);
        }

        // Запуск двунаправленного обмена данными между клиентом и сервером
        char buffer[4096];
        int bytes;

        while ((bytes = SSL_read(ssl, buffer, sizeof(buffer))) > 0) {
            write(remote_socket, buffer, bytes);

            bytes = read(remote_socket, buffer, sizeof(buffer));
            SSL_write(ssl, buffer, bytes);
        }

        // Закрытие соединений
        close(client_socket);
        close(remote_socket);
        printf("Closed connection from %s\n", inet_ntoa(client_addr.sin_addr));
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }

    // Закрытие серверного сокета
    close(server_socket);
}


int main() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX *ctx = create_ssl_context();

    create_ssl_tunnel(ctx, LOCAL_PORT);

    SSL_CTX_free(ctx);
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
