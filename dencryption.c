// decryption.c
#include <stdio.h>
#include <stdlib.h>

#define BUFFER_SIZE 1024

int decryptWithOpenSSL(const char *inputFile, const char *output, const char *key) {
    char buffer[BUFFER_SIZE];
    char keytu[BUFFER_SIZE];

    FILE *keyFilePtr = fopen(key, "r");
    if (keyFilePtr == NULL) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    if (fscanf(keyFilePtr, "%s", keytu) != 1) {
        fprintf(stderr, "Error reading key from file.\n");
        fclose(keyFilePtr);
        return EXIT_FAILURE;
    }

    fclose(keyFilePtr);

    char command[256];
    snprintf(command, sizeof(command), "openssl enc -d -engine bee2evp -belt-cbc128 -in %s -out %s -k %s",
             inputFile, output, keytu);

    if (system(command) == -1) {
        perror("system");
        return EXIT_FAILURE;
    }

    FILE *decryptedFile = fopen(output, "r");
    if (decryptedFile == NULL) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    printf("Decrypted contents:\n");

    while (fgets(buffer, BUFFER_SIZE, decryptedFile) != NULL) {
        printf("%s", buffer);
    }

    fclose(decryptedFile);

    return EXIT_SUCCESS;
}
