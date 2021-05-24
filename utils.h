#include <stdio.h>
#include <stdlib.h>
#include <jansson.h>

void show_message(char *message)
{
    fprintf(stderr, "[Message]: %s\n", message);
}

size_t generate_account_number()
{
    return 1000000000 + rand() / (RAND_MAX / (2000000000 - 1000000000 + 1) + 1);
}

void object_to_string(json_t *object, const char *key)
{
    fprintf(stderr, "%s, %s\n", key, json_string_value(json_object_get(object, key)));
}

void object_to_real(json_t *object, const char *key)
{
    fprintf(stderr, "%s, %f", key, json_real_value(json_object_get(object, key)));
}

void object_to_int(json_t *object, const char *key)
{
    fprintf(stderr, "%s, %lli\n", key, json_integer_value(json_object_get(object, key)));
}

char *remove_garbage_chars(char *str)
{

    size_t str_len = strlen(str);
    fprintf(stderr, "%s -> (%s, %lu)\n", __func__, str, str_len);
    size_t end = 0;
    for (size_t i = str_len - 1; i > 0; i--)
    {
        if (str[i] == '}')
        {
            end = i;
        }
    }
    end += 1UL;
    fprintf(stderr, "Endpoint: %lu\n", end);
    char *_str = (char *)calloc(end, sizeof(char));
    strncpy(_str, str, end);

    fprintf(stderr, "%s -> (%s)\n", __func__, str);

    return _str;
}

char *trim_string(char *str)
{
    str = remove_garbage_chars(str);

    size_t str_len = strlen(str);

    int last_character = (int)str[str_len - 1];
    fprintf(stderr, "%s -> (%s, %lu, %d)\n", __func__, str, str_len, (char)last_character);
    if (last_character < 0)
    {
        char *_str = (char *)calloc(str_len - 1, sizeof(char));
        strncpy(_str, str, str_len - 1);
        return _str;
    }
    else
        return str;
}

void save_data(Bank **bank)
{
    FILE *fp = fopen("nginx_sgx_bank/storage.dat", "w");

    if (*bank != NULL)
    {
        exit(1);
    }
    for (size_t i = 0; i > (*bank)->size; i++)
    {
        fprintf(fp, "%s\t%lld\t%f\n", (*bank)->users[i]->username, (*bank)->balances[i]->account_number, (*bank)->balances[i]->balance);
    }
}