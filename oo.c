// Получаем размер файла от клиента
size_t file_size;
if (SSL_read(ssl, &file_size, sizeof(file_size)) <= 0)
{
    handleErrors();
}
        int final_len;
        if (EVP_DecryptFinal_ex(ctx, received_data + total_received + last_decrypted_len, &final_len) != 1)
        {
            handleErrors();
        }


printf("Received file size: %zu\n", file_size);

// Получаем размер блока от клиента
size_t block_size;
if (SSL_read(ssl, &block_size, sizeof(block_size)) <= 0)
{
    handleErrors();
}

printf("Received block size: %zu\n", block_size);

// Выделяем буфер для зашифрованных данных
unsigned char *ciphertext = (unsigned char *)malloc(block_size);
if (!ciphertext)
{
    fprintf(stderr, "Memory allocation failed.\n");
    exit(EXIT_FAILURE);
}

// Общий буфер для приема данных частями
unsigned char *received_data = (unsigned char *)malloc(file_size);
if (!received_data)
{
    fprintf(stderr, "Memory allocation failed.\n");
    exit(EXIT_FAILURE);
}

size_t total_received = 0;
while (total_received < file_size)
{
    // Принимаем размер текущего блока
    size_t chunk_size;
    if (SSL_read(ssl, &chunk_size, sizeof(chunk_size)) <= 0)
    {
        handleErrors();
    }

    // Принимаем зашифрованные данные частями
    int bytes_received = SSL_read(ssl, ciphertext, chunk_size);
    if (bytes_received <= 0)
    {
        handleErrors();
    }

    // Дешифруем данные
    int decrypted_len;
    if (EVP_DecryptUpdate(ctx, received_data + total_received, &decrypted_len, ciphertext, bytes_received) != 1)
    {
        handleErrors();
    }

    total_received += decrypted_len;

    // Выводим прогресс
    printProgressBar(total_received, file_size);
}

free(ciphertext);

// Расшифровка последнего блока
int final_len;
if (EVP_DecryptFinal_ex(ctx, received_data + total_received, &final_len) != 1)
{
    handleErrors();
}

total_received += final_len;

printf("\nReceived %zu bytes in total.\n", total_received);

// Обрабатываем расшифрованные данные (если нужно)

// Освобождаем память
free(received_data);