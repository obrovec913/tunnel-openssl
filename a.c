#include <openssl/evp.h>
#include <stdio.h>

// Функция обратного вызова, которая будет вызвана для каждого алгоритма
static void print_cipher(const char *name, void *arg) {
    printf("%s\n", name);
}

int main() {
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG, NULL);
    // Вывод всех доступных алгоритмов шифрования
    EVP_CIPHER_names_do_all(NULL, print_cipher, NULL);

    return 0;
}
