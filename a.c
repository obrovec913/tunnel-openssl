#include <openssl/evp.h>
#include <stdio.h>

// Функция обратного вызова, которая будет вызвана для каждого алгоритма
static void print_cipher(const OBJ_NAME *obj, void *arg)
{
    printf("%s\n", obj->name);
}

int main()
{
    // Вывод всех доступных алгоритмов шифрования
    EVP_CIPHER_names_do_all(NULL, print_cipher, NULL);

    return 0;
}
