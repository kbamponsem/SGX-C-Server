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

#include "Enclave_t.h"  /* print_string */
#include <string>
#include <string.h>
#include <stdio.h>
#include "/opt/intel/sgxssl/include/openssl/ssl.h"
#include "/opt/intel/sgxssl/include/openssl/err.h"



double secure_add(double a, double b)
{
    return a+b;
}


static SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();

    // ctx = SSL_CTX_new(method);
    // if (!ctx)
    // {
    //     perror("Unable to create SSL context");
    //     ERR_print_errors_fp(stderr);
    //     exit(EXIT_FAILURE);
    // }

    // SSL_CTX_set_ecdh_auto(ctx, 1);

    // /* Set the key and cert */
    // if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0)
    // {
    //     ERR_print_errors_fp(stderr);
    //     exit(EXIT_FAILURE);
    // }

    // if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0)
    // {
    //     ERR_print_errors_fp(stderr);
    //     exit(EXIT_FAILURE);
    // }

    return ctx;
}
void ecall_start_tls_server(void)
{
    int sock;
    SSL_CTX *ctx;

    // ("OPENSSL Version = %s", SSLeay_version(SSLEAY_VERSION));
    // // init_openssl();
    ctx = create_context();
    // configure_context(ctx);

    // sock = create_socket_server(4433);
    // if(sock < 0) {
    //     printe("create_socket_client");
    //     exit(EXIT_FAILURE);
    // }

    // /* Handle SSL/TLS connections */
    // while(1) {
    //     struct sockaddr_in addr;
    //     int len = sizeof(addr);
    //     SSL *cli;
    //     unsigned char read_buf[1024];
    //     int r = 0;
    //     printl("Wait for new connection...");
    //     int client = accept(sock, (struct sockaddr*)&addr, &len);
    //     if (client < 0) {
    //         printe("Unable to accept");
    //         exit(EXIT_FAILURE);
    //     }

	// cli = SSL_new(ctx);
    //     SSL_set_fd(cli, client);
	// if (SSL_accept(cli) <= 0) {
    //         printe("SSL_accept");
    //         exit(EXIT_FAILURE);
    //     }
		
    //     printl("ciphersuit: %s", SSL_get_current_cipher(cli)->name);
    //     /* Receive buffer from TLS server */
    //     r = SSL_read(cli, read_buf, sizeof(read_buf));
    //     printl("read_buf: length = %d : %s", r, read_buf);
    //     memset(read_buf, 0, sizeof(read_buf));        
        
    //     printl("Close SSL/TLS client");
    //     SSL_free(cli);
    //     sgx_close(client);
    // }

    // sgx_close(sock);
    // SSL_CTX_free(ctx);
    // cleanup_openssl();
}


