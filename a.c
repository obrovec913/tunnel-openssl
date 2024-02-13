#include <openssl/evp.h>
#include <stdio.h>

// Функция обратного вызова, которая будет вызвана для каждого алгоритма
static void print_cipher(const char *name, void *arg) {
    printf("%s\n", name);
}

int main() {
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG, NULL);
    // Вывод всех доступных алгоритмов шифрования
    //EVP_CIPHER_names_do_all(NULL, print_cipher, NULL);
     OpenSSL_add_all_algorithms();

    // Имя алгоритма, который вы хотите инициализировать
    const char *algorithm_name = "belt-cbc128"; // Например, алгоритм шифрования BEE2EVP

    // Получение алгоритма из интерфейса EVP
    const EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, algorithm_name, NULL);

    if (cipher == NULL) {
        // Обработка ошибки
        fprintf(stderr, "Failed to fetch cipher %s\n", algorithm_name);
        return 1;
    }
    return 0;
}
