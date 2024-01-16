// main.c
#include <stdio.h>
#include <stdlib.h>
#include "encryption.c"
#include "dencryption.c"

int main() {
    const char *inputFile = "мама мыла сашу";
    const char *encryptedFile = "encrypted.txt";
    const char *decryptedFile = "decrypted.txt";
    const char *key = "symmetric_key.txt";

    if (encryptWithOpenSSL(inputFile, encryptedFile, key) == EXIT_SUCCESS) {
        printf("Encryption successful.\n");
    } else {
        fprintf(stderr, "Encryption failed.\n");
        return EXIT_FAILURE;
    }

    if (decryptWithOpenSSL(encryptedFile, decryptedFile, key) == EXIT_SUCCESS) {
        printf("Decryption successful.\n");
    } else {
        fprintf(stderr, "Decryption failed.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
