#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

// Функция для обработки ошибок OpenSSL
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

// Функция для шифрования данных с использованием алгоритма belt-cbc128
void encrypt_belt_cbc(const unsigned char *plaintext, size_t plaintext_len,
                      const unsigned char *key, const unsigned char *iv,
                      unsigned char **ciphertext, size_t *ciphertext_len)
{
    // Загрузка плагина bee2evp
    ENGINE_load_builtin_engines();
    ENGINE *engine = ENGINE_by_id("bee2evp");

    if (!engine)
        handleErrors();

    // Создание и инициализация контекста шифрования
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handleErrors();

    // Получение алгоритма шифрования belt-cbc128
    const EVP_CIPHER *cipher = EVP_get_cipherbyname("belt-cbc128");
    if (!cipher)
        handleErrors();

    // Инициализация контекста шифрования с ключом и IV
    if (EVP_EncryptInit_ex(ctx, cipher, engine, key, iv) != 1)
        handleErrors();

    // Выделение памяти для зашифрованных данных
    *ciphertext = (unsigned char *)malloc(plaintext_len + EVP_CIPHER_block_size(cipher));
    if (!*ciphertext)
        handleErrors();

    int len;
    // Шифрование данных
    if (EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len) != 1)
        handleErrors();

    *ciphertext_len = len;

    // Завершение шифрования и получение последних блоков
    if (EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len) != 1)
        handleErrors();

    *ciphertext_len += len;

    // Освобождение ресурсов
    ENGINE_free(engine);
    EVP_CIPHER_CTX_free(ctx);
}

// Функция для дешифрования данных с использованием алгоритма belt-cbc128
void decrypt_belt_cbc(const unsigned char *ciphertext, size_t ciphertext_len,
                      const unsigned char *key, const unsigned char *iv,
                      unsigned char **decryptedtext, size_t *decryptedtext_len)
{
    // Загрузка плагина bee2evp
    ENGINE *engine = ENGINE_by_id("bee2evp");
    if (!engine)
        handleErrors();

    // Создание и инициализация контекста дешифрования
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handleErrors();

    // Получение алгоритма шифрования belt-cbc128
    const EVP_CIPHER *cipher = EVP_get_cipherbyname("belt-cbc128");
    if (!cipher)
        handleErrors();

    // Инициализация контекста дешифрования с ключом и IV
    if (EVP_DecryptInit_ex(ctx, cipher, engine, key, iv) != 1)
        handleErrors();

    // Выделение памяти для дешифрованных данных
    *decryptedtext = (unsigned char *)malloc(ciphertext_len);
    if (!*decryptedtext)
        handleErrors();

    int len;
    // Дешифрование данных
    if (EVP_DecryptUpdate(ctx, *decryptedtext, &len, ciphertext, ciphertext_len) != 1)
        handleErrors();

    *decryptedtext_len = len;

    // Завершение дешифрования и получение последних блоков
    if (EVP_DecryptFinal_ex(ctx, *decryptedtext + len, &len) != 1)
        handleErrors();

    *decryptedtext_len += len;

    // Освобождение ресурсов
    ENGINE_free(engine);
    EVP_CIPHER_CTX_free(ctx);
}

int main()
{
    // Входные данные
    const unsigned char *plaintext = (const unsigned char *)"Hello, Bee2evp!";
    const size_t plaintext_len = strlen((const char *)plaintext);

    // Ключ и IV в шестнадцатеричном формате (в реальном приложении должны быть безопасными)
    const unsigned char *key = (const unsigned char *)"0123456789ABCDEF";
    const unsigned char *iv = (const unsigned char *)"FEDCBA9876543210";

    // Переменные для хранения зашифрованных и дешифрованных данных
    unsigned char *ciphertext = NULL;
    size_t ciphertext_len;

    // Вызов функции для шифрования данных
    encrypt_belt_cbc(plaintext, plaintext_len, key, iv, &ciphertext, &ciphertext_len);

    // Вывод результатов шифрования
    printf("Plaintext: %s\n", plaintext);
    printf("Ciphertext (hex): ");
    for (size_t i = 0; i < ciphertext_len; ++i)
    {
        printf("%02X", ciphertext[i]);
    }
    printf("\n");

    // Переменные для хранения дешифрованных данных
    unsigned char *decryptedtext = NULL;
    size_t decryptedtext_len;

    // Вызов функции для дешифрования данных
    decrypt_belt_cbc(ciphertext, ciphertext_len, key, iv, &decryptedtext, &decryptedtext_len);

    // Вывод результатов дешифрования
    printf("Decrypted Text: %s\n", decryptedtext);

    // Освобождение выделенной памяти
    free(ciphertext);
    free(decryptedtext);

    return 0;
}
