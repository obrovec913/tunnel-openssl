#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/ssl.h>

#define PORT 12345
#define MAX_BUFFER_SIZE 1024

void handleErrors() {
    fprintf(stderr, "Error occurred.\n");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

SSL_CTX *createSSLContext() {
    SSL_CTX *ctx;

    // Инициализация OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Создание нового SSL_CTX
    if ((ctx = SSL_CTX_new(SSLv23_server_method())) == NULL)
        handleErrors();

    // Загрузка корневого сертификата
    if (SSL_CTX_load_verify_locations(ctx, "./keys/root_cert.pem", NULL) != 1)
        handleErrors();

    // Загрузка сертификата и ключа сервера
    if (SSL_CTX_use_certificate_file(ctx, "./keys/server_cert.pem", SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, "./keys/server_key.pem", SSL_FILETYPE_PEM) != 1)
        handleErrors();

    // Проверка правильности ключа
    if (SSL_CTX_check_private_key(ctx) != 1)
        handleErrors();

    return ctx;
}

int main() {
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN |
                            OPENSSL_INIT_LOAD_CONFIG,
                        NULL);

    ENGINE *engine = ENGINE_by_id("bee2evp");
    if (!engine)
    {
        fprintf(stderr, "Failed to load bee2evp engine: %s\n", ERR_error_string(ERR_get_error(), NULL));
        handleErrors();
    }
      // Создание SSL контекста
    SSL_CTX *ssl_ctx = createSSLContext();

    // Устанавливаем серверный сокет
    int sockfd, connfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t len;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        handleErrors();

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
        handleErrors();

    if (listen(sockfd, 5) < 0)
        handleErrors();

    while (1) {  // бесконечный цикл для прослушивания порта
        len = sizeof(client_addr);
        connfd = accept(sockfd, (struct sockaddr*)&client_addr, &len);
        if (connfd < 0)
            handleErrors();

        // Создание SSL структуры
        SSL *ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, connfd);

        // Устанавливаем SSL соединение
        if (SSL_accept(ssl) != 1)
            handleErrors();

        // Получаем зашифрованные данные от клиента
        unsigned char ciphertext[MAX_BUFFER_SIZE];
        int ciphertext_len = SSL_read(ssl, ciphertext, sizeof(ciphertext));

        // Расшифровываем данные
        unsigned char decrypted_text[MAX_BUFFER_SIZE];
        int decrypted_len;

        // Инициализация контекста шифрования с ключом и IV
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
            handleErrors();

        // (как в предыдущем коде)

        // Вывод расшифрованного сообщения
        printf("Decrypted Text: %s\n", decrypted_text);

        // Освобождение контекста шифрования
        EVP_CIPHER_CTX_free(ctx);

        close(connfd);
        SSL_free(ssl);
    }

    close(sockfd);
    SSL_CTX_free(ssl_ctx);

    return 0;
}