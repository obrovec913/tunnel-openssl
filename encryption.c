// encryption.c
#include <stdio.h>
#include <stdlib.h>

#define BUFFER_SIZE 1024

int encryptWithOpenSSL(const char *input, const char *outputFile, const char *key) {
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

    char tempFileName[] = "/tmp/tempfileXXXXXX";
    int tempFileDescriptor = mkstemp(tempFileName);
    if (tempFileDescriptor == -1) {
        perror("mkstemp");
        return EXIT_FAILURE;
    }

    FILE *tempFile = fdopen(tempFileDescriptor, "w");
    if (tempFile == NULL) {
        perror("fdopen");
//        close(tempFileDescriptor);
        return EXIT_FAILURE;
    }

    fprintf(tempFile, "%s", input);
    fclose(tempFile);

    char command[256];
    snprintf(command, sizeof(command), "openssl enc -engine bee2evp -belt-cbc128 -in %s -out %s -k %s",
             tempFileName, outputFile, keytu);

    if (system(command) == -1) {
        perror("system");
        return EXIT_FAILURE;
    }

    if (remove(tempFileName) != 0) {
        perror("remove");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
