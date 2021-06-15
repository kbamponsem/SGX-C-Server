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
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sgx_tprotected_fs.h>
#include <sgx_trts.h>
#include <unordered_map>
#include "UserEnclave_t.h" /* print_string */
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>

#define KEY_LENGTH 2048

static All_Users all_users[1];
char *pri_key = NULL; // private key
char *pub_key = NULL;

static std::unordered_map<big_int, char *> sessions;

int create_session(big_int id, char *encrypted_session_id);
char *get_session_id(big_int id);
char *decrypt_session_key(char *encrypted_session_key);
int remove_session_id(big_int id);

int users_in_enclave()
{
    return sgx_is_within_enclave(&(all_users->users[0].username), sizeof(all_users));
}

int create_account(char *username, char *password, big_int acc_number)
{
    Account_U user = {username, password, acc_number};

    size_t curr_list_size = all_users->size;

    size_t new_list_size = curr_list_size + 1;

    all_users->users[curr_list_size] = user;

    all_users->size = new_list_size;

    return 1;
}

int login(big_int account_number, char *password)
{
    for (size_t i = 0; i < all_users->size; i++)
    {
        if (all_users->users[i].account_number == account_number && strcmp(all_users->users[i].password, password) == 0)
        {
            return 1;
        }
    }
    return 0;
}

void get_pub_key(char *pub_key_cpy)
{
    strncpy(pub_key_cpy, pub_key, strlen(pub_key));
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
    // do
    // {
    message = (u_char *)calloc(4098, sizeof(u_char));
    stat = RSA_private_decrypt(strlen(encrypted_session_key), (const u_char *)encrypted_session_key, message, r, RSA_PKCS1_PADDING);
    // } while (stat < 0);

    return (char *)message;
}
int generate_keys()
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

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);

    PEM_write_bio_RSA_PUBKEY(pub, keypair);

    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    pri_key = (char *)malloc(pri_len + 1);
    pub_key = (char *)malloc(pub_len + 1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    BIO_free_all(pub);
    BIO_free_all(pri);

    // sessions = new std::map<big_int, char *>();

    return ret;
}

int create_session(big_int id, char *encrypted_session_id)
{
    std::unordered_map<big_int, char *>::const_iterator obj = sessions.find(id);
    char *session_id = decrypt_session_key(encrypted_session_id);

    if (obj != sessions.end())
        if (obj->first == id)
            return 0;
        else
        {
            sessions.insert(std::pair<big_int, char *>(id, session_id));
            return 1;
        }
    else
    {
        sessions.insert(std::pair<big_int, char *>(id, session_id));
        return 1;
    }
    return 0;
}

void get_user_session_id(big_int id, char *session_id)
{
    char *_session_id = get_session_id(id);
    strncpy(session_id, _session_id, strlen(_session_id));
}
char *get_session_id(big_int id)
{
    std::unordered_map<big_int, char *>::const_iterator obj = sessions.find(id);

    if (obj != sessions.end())
        return obj->second;
    else
        return NULL;
}

int remove_session_id(big_int id)
{
    std::unordered_map<big_int, char *>::const_iterator obj = sessions.find(id);

    if (obj != sessions.end())
        if (obj->first == id)
        {
            sessions.erase(id);
            return 1;
        }
    return 0;
}

int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx, 
             EVP_CIPHER_CTX *d_ctx)
{
//   int i, nrounds = 5;
  unsigned char key[32], iv[16];
  
//   /*
//    * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
//    * nrounds is the number of times the we hash the material. More rounds are more secure but
//    * slower.
//    */
//   i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
//   if (i != 32) {
//     return -1;
//   }

  EVP_CIPHER_CTX_init(e_ctx);
  EVP_EncryptInit_ex(e_ctx, EVP_aes_256_gcm(), NULL, key, iv);
  EVP_CIPHER_CTX_init(d_ctx);
  EVP_DecryptInit_ex(d_ctx, EVP_aes_256_gcm(), NULL, key, iv);

  return 0;
}