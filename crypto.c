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
        fclose(tempFileDescriptor);
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

int main() {
    const char *inputFile = "мама мыла сашу";
    const char *outputFile = "encrypted.txt";
    const char *key = "symmetric_key.txt";

    if (encryptWithOpenSSL(inputFile, outputFile, key) == EXIT_SUCCESS) {
        printf("Encryption successful.\n");
    } else {
        fprintf(stderr, "Encryption failed.\n");
    }

    return EXIT_SUCCESS;
}
