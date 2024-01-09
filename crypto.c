#include <stdio.h>
#include <stdlib.h>

#define BUFFER_SIZE 1024

int encryptWithOpenSSL(const char *inputFile, const char *outputFile, const char *key) {
    FILE *fp;
    char buffer[BUFFER_SIZE];
    char key[BUFFER_SIZE];

    // Открываем файл с ключом
    FILE *keyFilePtr = fopen(key, "r");
    if (keyFilePtr == NULL) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    // Считываем ключ из файла
    if (fscanf(keyFilePtr, "%s", key) != 1) {
        fprintf(stderr, "Error reading key from file.\n");
        fclose(keyFilePtr);
        return EXIT_FAILURE;
    }

    fclose(keyFilePtr);

    // Формируем команду с использованием аргументов функции
    char command[256];
    snprintf(command, sizeof(command), "openssl  enc -engine bee2evp -belt-cbc128 -in %s -out %s -k %s", inputFile, outputFile, key);

    // Открываем канал для выполнения команды и чтения её вывода
    fp = popen(command, "r");
    if (fp == NULL) {
        perror("popen");
        return EXIT_FAILURE;
    }

    // Читаем вывод команды из канала
    while (fgets(buffer, BUFFER_SIZE, fp) != NULL) {
        printf("%s", buffer);  // или сохраните в вашу переменную
    }

    // Закрываем канал
    if (pclose(fp) == -1) {
        perror("pclose");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int main() {
    const char *inputFile = "README.md";
    const char *outputFile = "encrypted.txt";
    const char *key = "symmetric_key.txt";

    if (encryptWithOpenSSL(inputFile, outputFile, key) == EXIT_SUCCESS) {
        printf("Encryption successful.\n");
    } else {
        fprintf(stderr, "Encryption failed.\n");
    }

    return EXIT_SUCCESS;
}
