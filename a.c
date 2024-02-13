#include <openssl/evp.h>
#include <stdio.h>

// Функция обратного вызова, которая будет вызвана для каждого алгоритма
static void print_cipher(const char *name, void *arg)
{
    printf("%s\n", name);
}

int main()
{
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG, NULL);
    // Вывод всех доступных алгоритмов шифрования
    // EVP_CIPHER_names_do_all(NULL, print_cipher, NULL);
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    // Имя алгоритма, который вы хотите инициализировать
    const char *algorithm_name = "belt-cbc128"; // Например, алгоритм шифрования BEE2EVP
    SSL_CTX *ssl_ctx = SSL_CTX_new(SSLv23_method());
    if (!ssl_ctx)
    {
        // Обработка ошибки создания контекста SSL
        fprintf(stderr, "Failed to fetch cipher %s\n", algorithm_name);  
    }

    // Установка списка алгоритмов шифрования на "ALL"
    if (!SSL_CTX_set_cipher_list(ssl_ctx, algorithm_name))
    {
        // Обработка ошибки установки списка алгоритмов шифрования
        // Обработка ошибки
        fprintf(stderr, "Failed to fetch cipher %s\n", algorithm_name);
        return 1;
    }

    
    return 0;
}
