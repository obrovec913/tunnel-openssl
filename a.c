#include <openssl/evp.h>
#include <stdio.h>
#include <openssl/ssl.h>

int main()
{
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG, NULL);
    // Вывод всех доступных алгоритмов шифрования
    // EVP_CIPHER_names_do_all(NULL, print_cipher, NULL);
    SSL_library_init();
    SSL_load_error_strings();
    //ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    
    
    // Имя алгоритма, который вы хотите инициализировать
    const char *algorithm_name = "belt-cbc128"; // Например, алгоритм шифрования BEE2EVP
    const char *ciphersuites = "belt-dwp-tls";
   const EVP_CIPHER *cipheraa = EVP_get_cipherbyname(ciphersuites); 
    EVP_add_cipher(cipheraa);

    EVP_CIPHER *cipher;


    printf("Available ciphers:\n");
    for (int nid = 1; nid < 3000; nid++)
    {
        cipher = EVP_get_cipherbynid(nid);
        if (cipher != NULL)
        {
            const char *name = EVP_CIPHER_name(cipher);
            printf("%s\n", name);
        }
    }

    
    //OpenSSL_add_all_algorithms();

    // Создание контекста SSL/TLS
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());

    // Установка списка алгоритмов шифрования
    const char *cipherd = "belt-dwp-tls";
    if (!SSL_CTX_set_cipher_list(ssl_ctx, cipherd)) {
        fprintf(stderr, "Failed to set cipher list\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // Далее можно использовать ssl_ctx для создания SSL-соединений

    // Освобождение ресурсов
    SSL_CTX_free(ssl_ctx);

    // Очистка OpenSSL
    EVP_cleanup();
    //ERR_free_strings();

    return 0;
}
