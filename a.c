#include <openssl/evp.h>
#include <stdio.h>
#include <openssl/ssl.h>

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
        fprintf(stderr, "Failed to fetch  %s\n", algorithm_name);
    }
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

    // Установка списка алгоритмов шифрования на "ALL"
    if (!SSL_CTX_set_cipher_list(ssl_ctx, ciphersuites))
    {
        // Обработка ошибки установки списка алгоритмов шифрования
        // Обработка ошибки
        fprintf(stderr, "Failed to fetch cipher %s\n", ciphersuites);
        return 1;
    }

    return 0;
}
