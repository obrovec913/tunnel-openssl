#include <stdio.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
int main()
{
    ENGINE_load_builtin_engines();
    ENGINE_register_all_complete();
    printf("OpenSSL Version: %s\n", OpenSSL_version(OPENSSL_VERSION));
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN |
                            OPENSSL_INIT_LOAD_CONFIG,
                        NULL);

    const CONF *conf = NCONF_default();
    if (conf)
    {
        NCONF_dump_fp(conf, stdout);

    }
    else
    {
        fprintf(stderr, "Failed to load OpenSSL configuration.\n");
    }

    // Получаем список всех доступных движков
    ENGINE *engine_list = ENGINE_get_first();
    while (engine_list != NULL)
    {
        printf("Доступный движок: %s\n", ENGINE_get_id(engine_list));
        engine_list = ENGINE_get_next(engine_list);
    }

    // Теперь попробуем получить движок "bee2evp"
    ENGINE *engine = ENGINE_by_id("bee2evp");
    if (engine == NULL)
    {
        fprintf(stderr, "Ошибка: не удалось загрузить движок Bee2evp\n");
        ERR_print_errors_fp(stderr);

        // Выведем список ошибок, чтобы увидеть, что происходит
        ERR_print_errors_fp(stderr);
        return -1;
    }

    printf("Движок успешно загружен: %s\n", ENGINE_get_id(engine));

    // Тут можно использовать загруженный движок для выполнения необходимых задач

    ENGINE_free(engine);
    return 0;
}
