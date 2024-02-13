#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG, NULL);
    //   EVP_CIPHER_fetch();
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL)
    {
        printf("Failed to create OpenSSL library context\n");
        return 1;
    }

    // Получение алгоритма по имени
    const char *algorithm_name = "belt-ecb128";
    const EVP_CIPHER *cipherx = EVP_CIPHER_fetch(libctx, algorithm_name, NULL);
    if (cipherx == NULL)
    {
        printf("Failed to fetch cipher %s\n", algorithm_name);
        return 1;
    }
      printf("Algorithm name: %s\n", EVP_CIPHER_get0_name(cipherx));
    printf("Algorithm description: %s\n", EVP_CIPHER_get0_description(cipherx));
    printf("Algorithm type: %d\n", EVP_CIPHER_get_type(cipherx));

    // const char *algorithm_name = "belt-ecb128";
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(algorithm_name);
    if (cipher != NULL)
    {
        // Получение параметров алгоритма
        int nid = EVP_CIPHER_nid(cipher);
        int type = EVP_CIPHER_type(cipher);
        int block_size = EVP_CIPHER_block_size(cipher);
        int key_length = EVP_CIPHER_key_length(cipher);
        int iv_length = EVP_CIPHER_iv_length(cipher);

        // Вывод параметров
        printf("Algorithm name: %s\n", algorithm_name);
        printf("NID: %d\n", nid);
        printf("Type: %d\n", type);
        printf("Block size: %d\n", block_size);
        printf("Key length: %d\n", key_length);
        printf("IV length: %d\n", iv_length);
    }
    else
    {
        printf("Algorithm not found: %s\n", algorithm_name);
    }

    return 0;
}
