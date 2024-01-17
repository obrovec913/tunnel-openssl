#include <openssl/engine.h>
#include <openssl/evp.h>
//#include <openssl/bee2evp.h>
int main() {
    // Инициализация OpenSSL и загрузка движка Bee2evp
    ENGINE_load_openssl();
    SSL_library_init();
    ENGINE_load_builtin_engines();
    ENGINE_register_all_complete();

    // Получение указателя на движок Bee2evp
    ENGINE *engine = ENGINE_by_id("bee2evp");
    if (!engine) {
        fprintf(stderr, "Ошибка: не удалось загрузить движок Bee2evp\n");
        return 1;
    }

    // Использование движка Bee2evp для шифрования данных
    // Ваш код для шифрования данных здесь

    // Освобождение ресурсов
    ENGINE_free(engine);
    EVP_cleanup();
    
    return 0;
}
