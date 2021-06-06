#include <stdio.h>
#include <stdlib.h>
#include <jansson.h>
#include <stdarg.h>

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

char *add_semi_colon(char *str)
{
    strcat(str, "; ");
    return str;
}

char *strappend(char *dest, char *src)
{
    size_t src_len = strlen(src);
    size_t dest_len = strlen(dest);

    char *__temp = dest;

    dest = (char *)calloc(dest_len + src_len, sizeof(char));

    strcpy(dest, __temp);
    strcat(dest, src);

    return dest;
}
int command_to_shell(const char *format, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, format);
    int r = vsnprintf(buf, BUFSIZ, format, ap);
    va_end(ap);

    char *base_command = "gnome-terminal -- /bin/sh -c \'";
    char *end = "sleep 10;\'";

    char *command = strappend(strappend(base_command, buf), end);

    fprintf(stderr, "Command: %s\n", command);

    int results = system(command);

    return results;
}

char *encrypt_string(char *data)
{
    size_t str_length = strlen(data);

    char *ret = (char *)calloc(str_length, sizeof(char));
    for (size_t i = 0; i < str_length - 1; i++)
    {
        printf("%c\t%d\t%c\t%d\n", data[i], data[i], data[i] + 1, data[i] + 1);
        char c = data[i];
        c = (char)((int)c+ 1);
        data[i] = c;
    }
    for (size_t i = 0; i < str_length; i++)
    {
        printf("%c\t%d\t%c\t%d\n", data[i], data[i], data[i] + 1, data[i] + 1);
    }
    ret = data;
    return ret;
}