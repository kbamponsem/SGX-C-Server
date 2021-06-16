/*
 * Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "BalanceEnclave_t.h" /* print_string */
#include <string>
#include <string.h>
#include <stdio.h>
#include <sgx_trts.h>
#include <unordered_map>
#include <unordered_set>
#include <cstring>
#include <vector>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define KEY_LENGTH 2048

static All_Balances all_balances[1];

static std::unordered_map<big_int, char *> sessions;
static std::unordered_set<char *> registered_users;

static char *pri_key = NULL; // private key
static char *pub_key = NULL;

char *get_session_id(big_int id);

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
    JSON() {}
    std::vector<std::pair<char *, char *>> get_object_elements();
    std::vector<char *> get_elements_list();
    char *json_dumps(std::vector<std::pair<char *, char *>> kv);
    int isInteger(float value)
    {
        long trunc = (long long int)value;
        return trunc == value ? 1 : 0;
    }

    char *get_type(char *value)
    {
        if (std::atof(value) == 0 && value[0] != '0')
        {
            return "string";
        }
        else if (isInteger(std::atof(value)) == 1)
        {
            return "int";
        }
        else
            return "float";
    }

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

    print_number(kv.size());
    for (size_t i = 0; i < kv.size(); i++)
    {
        v.push_back("\"");
        v.push_back(kv[i].first);
        v.push_back("\"");
        v.push_back(": ");

        v.push_back("\"");
        v.push_back(kv[i].second);
        v.push_back("\"");

        if (i != (kv.size() - 1))
            v.push_back(", ");
    }
    v.push_back("}");
    print_number(v.size());

    char *out = (char *)calloc(get_vector_str_len(v), sizeof(char));
    for (auto el : v)
    {
        strncat(out, el, strlen(el));
    }
    return out;
}

void initialize_balance(big_int id)
{

    Account_B b = {id, 23.5, 0};

    size_t curr_list_size = all_balances->size;

    size_t new_list_size = curr_list_size + 1;

    all_balances->balances[curr_list_size] = b;

    all_balances->size = new_list_size;
}
int add_balance(char *balance_string)
{
    return 0;
}

int operation(char *string)
{
    int found = 0;
    return found;
}
char *to_c_string(std::string s)
{
    return (char *)s.c_str();
}
void enclave2_get_pub_key(char *pub_key_cpy)
{
    strncpy(pub_key_cpy, pub_key, strlen(pub_key));
}

int delete_balance(char *string)
{
    int found = 0;

    return found;
}

RSA *create_RSA(u_char *pub_key, int type)
{
    RSA *r = RSA_new();
    BIO *bio = BIO_new_mem_buf(pub_key, -1);
    if (type == 1)
    {
        r = PEM_read_bio_RSAPublicKey(bio, &r, NULL, NULL);
    }
    else
    {
        r = PEM_read_bio_RSAPrivateKey(bio, &r, NULL, NULL);
    }

    return r;
}
char *decrypt_session_key(char *encrypted_session_key)
{
    int stat;
    RSA *r = create_RSA((u_char *)pri_key, 0);
    u_char *message;
    message = (u_char *)calloc(4096, sizeof(u_char));
    stat = RSA_private_decrypt((int)strlen(encrypted_session_key), (const u_char *)encrypted_session_key, message, r, RSA_PKCS1_PADDING);

    if (stat == -1)
        return NULL;
    return (char *)message;
}

int enclave2_create_session(big_int id, char *encrypted_session_id)
{
    all_balances->size = 0;
    std::unordered_map<big_int, char *>::const_iterator obj = sessions.find(id);

    if (obj != sessions.end())
        if (obj->first == id)
            return 0;
        else
        {
            sessions.insert(std::pair<big_int, char *>(id, encrypted_session_id));
            initialize_balance(id);

            print_number(all_balances->size);
            return 1;
        }
    else
    {
        sessions.insert(std::pair<big_int, char *>(id, encrypted_session_id));
        initialize_balance(id);

        print_number(all_balances->size);
        return 1;
    }

    return 0;
}

size_t get_vector_string_length(std::vector<char *> v)
{
    size_t big_size = 0;

    for (size_t i = 0; i < v.size(); i++)
    {
        big_size += strlen(v[i]);
    }
    return big_size;
}

char *join_string(std::vector<char *> str_vector)
{

    if (str_vector.size() != 0)
    {
        char *output = (char *)(get_vector_string_length(str_vector), sizeof(char));

        // print_string(output);
        return "HELLO";
    }
    return NULL;
}

int get_balance(big_int id, char *balance_string)
{
    char *key = "amount";
    std::vector<std::pair<char *, char *>> kv;
    std::vector<char *> json_string;
    JSON json;
    char *value;
    print_number(id);

    for (size_t i = 0; i < all_balances->size; i++)
    {
        if (all_balances->balances[i].account_number == id)
        {
            value = (char *)to_c_string(std::to_string(all_balances->balances[i].balance));
        }
    }

    if (value != NULL)
    {
        kv.push_back(std::pair<char *, char *>(key, value));

        char *out = json.json_dumps(kv);

        strncpy(balance_string, out, strlen(out));
        return 1;
    }

    return 0;
}

char *get_session_id(big_int id)
{
    std::unordered_map<big_int, char *>::const_iterator obj = sessions.find(id);

    if (obj != sessions.end())
        return obj->second;
    else
        return NULL;
}
int enclave2_generate_keys()
{
    int ret = 0;
    RSA *keypair = NULL;

    size_t pri_len = 0;

    BIGNUM *bne = NULL;

    unsigned long e = RSA_F4;

    bne = BN_new();
    ret = BN_set_word(bne, e);

    size_t pub_len = 0; // public key length

    keypair = RSA_new();
    ret = RSA_generate_key_ex(keypair, KEY_LENGTH, bne, NULL);

    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    ret = PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);

    ret = PEM_write_bio_RSA_PUBKEY(pub, keypair);

    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    pri_key = (char *)malloc(pri_len + 1);
    pub_key = (char *)malloc(pub_len + 1);

    ret = BIO_read(pri, pri_key, pri_len);
    ret = BIO_read(pub, pub_key, pub_len);

    BIO_free_all(pub);
    BIO_free_all(pri);

    return ret;
}