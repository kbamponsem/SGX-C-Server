#include <vector>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

size_t get_vector_str_len(std::vector<char *> v)
{
    size_t size = 0;

    for (size_t i = 0; i < v.size(); i++)
    {
        size += strlen((char *)v[i]);
    }
    return size;
}

class JSON
{
public:
    JSON(char *_JSON_String) : JSON_String(_JSON_String) {}
    std::vector<std::pair<char *, char *>> get_object_elements();
    std::vector<char *> get_elements_list();
    char *json_dumps(std::vector<std::pair<char *, char *>> kv);

private:
    char *JSON_String;
    std::vector<char *> elements;
};

std::vector<char *> JSON::get_elements_list()
{
    int right_brace_index;

    for (int i = strlen(JSON_String) - 1; i > -1; i--)
    {
        if (JSON_String[i] == '}')
        {
            right_brace_index = i;
        }
    }

    char *tok = strtok(JSON_String, "{");

    char *out = (char *)calloc(right_brace_index, sizeof(char));

    strncpy(out, tok, right_brace_index - 1);

    char *list_tok = strtok(out, ", :");

    std::vector<char *> list;

    while (list_tok != NULL)
    {
        list.push_back(list_tok);
        list_tok = strtok(NULL, ", :");
    }
    return list;
}

std::vector<std::pair<char *, char *>> JSON::get_object_elements()
{
    std::vector<std::pair<char *, char *>> kv;
    for (int i = 0; i < get_elements_list().size() - 1; i += 2)
    {
        kv.push_back(std::pair<char *, char *>(get_elements_list()[i], get_elements_list()[i + 1]));
    }
    return kv;
}

char *JSON::json_dumps(std::vector<std::pair<char *, char *>> kv)
{
    std::vector<char *> v;

    v.push_back("{");
    for (size_t i = 0; i < kv.size(); i++)
    {
        v.push_back(kv[i].first);
        v.push_back(": ");
        v.push_back(kv[i].second);
        if (i != (kv.size() - 1))
            v.push_back(", ");
    }
    v.push_back("}");

    char *out = (char *)calloc(get_vector_str_len(v), sizeof(char));
    for (auto el : v)
    {
        strncat(out, el, strlen(el));
    }

    return out;
}