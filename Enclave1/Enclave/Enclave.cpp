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

#include "Enclave_t.h" /* print_string */
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <sgx_trts.h>

All_Users *all_users = NULL;

void initialize_accounts(All_Users **all_users)
{
    *all_users = (All_Users *)calloc(1, sizeof(All_Users));
    (*all_users)->users = (Account_U **)calloc(1, sizeof(Account_U *));
    (*all_users)->size = 1;

    // for (size_t i = 0; i < (*all_users)->size; i++)
    // {
    //     Account_U *user = (Account_U *)calloc(1, sizeof(Account_U));

    //     user->username = NULL;
    //     user->account_number = 0;

    //     (*all_users)->users[i] = user;
    // }
}

enclave_op secure_subtract(double a, double b)
{
    enclave_op op1 = {a - b, sgx_is_within_enclave(&a, sizeof(a))};
    return op1;
}

void get_users()
{
    if (all_users == NULL)
        initialize_accounts(&all_users);
    serialize_data(all_users->users, all_users->size);
}

int add_user(Account_U *user)
{
    if (all_users == NULL)
        initialize_accounts(&all_users);

    // print username passed
    print_string((char*)user->username);

    size_t curr_list_size = all_users->size;

    size_t new_list_size = curr_list_size + 1;

    if (user->username != NULL)
    {
        Account_U **curr_users = all_users->users;

        Account_U **new_users = (Account_U **)calloc(new_list_size, sizeof(Account_U *));

        for (size_t i = 0; i < curr_list_size; i++)
        {
            new_users[i] = curr_users[i];
        }

        all_users->users = new_users;

        all_users->users[curr_list_size] = user;

        all_users->size = new_list_size;

        return 1;
    }
    else
        return 0;
}

int decrypt_message(char *encrypted_message)
{
    EVP_CIPHER_CTX *ctx;
    if (encrypted_message[0] == '1')
    {
        return 1;
    }
    else
        return 0;
}