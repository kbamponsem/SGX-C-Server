#include <stdio.h>
#include <stdlib.h>
#include <jansson.h>

void show_message(char* message) {
    fprintf(stderr, "[Message]: %s\n", message);
}

size_t generate_account_number()
{
    return 1000000000 + rand() / (RAND_MAX / (2000000000 - 1000000000 + 1) + 1);
}

void object_to_string(json_t* object, const char* key) {
    fprintf(stderr, "%s, %s\n",key, json_string_value(json_object_get(object, key)));
}

void object_to_real(json_t* object, const char* key) {
    fprintf(stderr, "%s, %f",key, json_real_value(json_object_get(object, key)));
}

void object_to_int(json_t* object, const char* key) {
    fprintf(stderr, "%s, %lli\n",key, json_integer_value(json_object_get(object, key)));
}