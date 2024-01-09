#include <stdio.h>
#include <stdlib.h>

#define BUFFER_SIZE 1024

int encryptWithOpenSSL(const char *input, const char *outputFile, const char *key) {
    char buffer[BUFFER_SIZE];
    char keytu[BUFFER_SIZE];

    // Открываем файл с ключом
    FILE *keyFilePtr = fopen(key, "r");
    if (keyFilePtr == NULL) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    // Считываем ключ из файла
    if (fscanf(keyFilePtr, "%s", keytu) != 1) {
        fprintf(stderr, "Error reading key from file.\n");
        fclose(keyFilePtr);
        return EXIT_FAILURE;
    }

    fclose(keyFilePtr);

    // Создаем уникальный временный файл
    char tempFileName[] = "/tmp/tempfileXXXXXX";
    int tempFileDescriptor = mkstemp(tempFileName);
    if (tempFileDescriptor == -1) {
        perror("mkstemp");
        return EXIT_FAILURE;
    }

    // Записываем данные во временный файл
    FILE *tempFile = fdopen(tempFileDescriptor, "w");
    if (tempFile == NULL) {
        perror("fdopen");
//        close(tempFileDescriptor);
        return EXIT_FAILURE;
    }

    fprintf(tempFile, "%s", input);
    fclose(tempFile);

    // Формируем команду с использованием аргументов функции
    char command[256];
    snprintf(command, sizeof(command), "openssl enc -engine bee2evp -belt-cbc128 -in %s -out %s -k %s",
             tempFileName, outputFile, keytu);

    // Выполняем команду
    if (system(command) == -1) {
        perror("system");
        return EXIT_FAILURE;
    }

    // Удаляем временный файл
    if (remove(tempFileName) != 0) {
        perror("remove");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int decryptWithOpenSSL(const char *inputFile, const char *output, const char *key) {
    char buffer[BUFFER_SIZE];
    char keytu[BUFFER_SIZE];

    // Открываем файл с ключом
    FILE *keyFilePtr = fopen(key, "r");
    if (keyFilePtr == NULL) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    // Считываем ключ из файла
    if (fscanf(keyFilePtr, "%s", keytu) != 1) {
        fprintf(stderr, "Error reading key from file.\n");
        fclose(keyFilePtr);
        return EXIT_FAILURE;
    }

    fclose(keyFilePtr);

    // Формируем команду с использованием аргументов функции
    char command[256];
    snprintf(command, sizeof(command), "openssl enc -d -engine bee2evp -belt-cbc128 -in %s -out %s -k %s",
             inputFile, output, keytu);

    // Выполняем команду
    if (system(command) == -1) {
        perror("system");
        return EXIT_FAILURE;
    }

    // Открываем дешифрованный файл и выводим его содержимое
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
