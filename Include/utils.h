#ifndef UTILS_H__
#define UTILS_H__

#include <stdio.h>
#include <stdlib.h>
#include <jansson.h>
#include <stdarg.h>

static inline void string2hexString(char *input, char *output)
{
    int loop;
    int i;

    i = 0;
    loop = 0;

    while (input[loop] != '\0')
    {
        sprintf((char *)(output + i), "%02X", input[loop]);
        loop += 1;
        i += 2;
    }
    // insert NULL at the end of the output string
    output[i++] = '\0';
}

static inline void show_message(char *message)
{
    fprintf(stderr, "[Message]: %s\n", message);
}

static inline void object_to_string(json_t *object, const char *key)
{
    fprintf(stderr, "%s, %s\n", key, json_string_value(json_object_get(object, key)));
}

static inline void object_to_real(json_t *object, const char *key)
{
    fprintf(stderr, "%s, %f", key, json_real_value(json_object_get(object, key)));
}

static inline void object_to_int(json_t *object, const char *key)
{
    fprintf(stderr, "%s, %lli\n", key, json_integer_value(json_object_get(object, key)));
}

static inline char *remove_garbage_chars(char *str)
{

    size_t str_len = strlen(str);
    size_t end = 0;
    for (size_t i = str_len - 1; i > 0; i--)
    {
        if (str[i] == '}')
        {
            end = i;
        }
    }
    end += 1UL;
    char *_str = (char *)calloc(end, sizeof(char));
    strncpy(_str, str, end);

    return _str;
}

static inline char *trim_string(char *str)
{
    if (str == NULL)
        return NULL;
    str = remove_garbage_chars(str);

    size_t str_len = strlen(str);

    int last_character = (int)str[str_len - 1];
    if (last_character < 0)
    {
        char *_str = (char *)calloc(str_len - 1, sizeof(char));
        strncpy(_str, str, str_len - 1);
        return _str;
    }
    else
        return str;
}

static inline char *add_semi_colon(char *str)
{
    strcat(str, "; ");
    return str;
}

static inline char *strappend(char *dest, char *src)
{
    size_t src_len = strlen(src);
    size_t dest_len = strlen(dest);

    char *__temp = dest;

    dest = (char *)calloc(dest_len + src_len, sizeof(char));

    strcpy(dest, __temp);
    strcat(dest, src);

    return dest;
}

#endif