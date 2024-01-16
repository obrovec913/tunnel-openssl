#include <stdio.h>
#include <openssl/obj_mac.h>

int main() {
    OpenSSL_add_all_algorithms();

    printf("Available ciphers:\n");

    OBJ_NAME_do_all(OBJ_NAME_TYPE_CIPHER_METH, NULL, [](const OBJ_NAME *obj_name) -> int {
        printf("%s\n", obj_name->name);
        return 1;
    });

    return 0;
}
