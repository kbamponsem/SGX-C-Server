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

static All_Balances all_balances[1];

char *get_balances()
{
    char *output;
    serialize_balance(&output, all_balances);
    return output;
}

int add_balance(char *balance_string)
{
    Account_B balance;

    /*
        For this step, user string would be encrypted with the Pk of Enclave1
    */
    balance_string_to_account(&balance, balance_string);
    size_t curr_list_size = all_balances->size;

    size_t new_list_size = curr_list_size + 1;

    if (balance.balance >= 0)
    {
        all_balances->balances[curr_list_size] = balance;

        all_balances->size = new_list_size;

        return 1;
    }
    else
        return 0;
}

int operation(char *string)
{
    int found = 0;
    return found;
}

int delete_balance(char *string)
{
    int found = 0;


    return found;
}