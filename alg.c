#include <stdio.h>
#include <openssl/obj_mac.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int print_cipher_names(const OBJ_NAME *obj_name) {
    printf("%s\n", obj_name->name);
    return 1;
}

int main() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    ERR_load_crypto_strings();  // Инициализация строк с описанием ошибок OpenSSL

    printf("Available ciphers:\n");

    OBJ_NAME_do_all(OBJ_NAME_TYPE_CIPHER_METH, print_cipher_names);

    ERR_print_errors_fp(stderr);  // Вывести ошибки OpenSSL

    return 0;
}
