# Setting up the project
One would have  to download nginx from source. This project requires that you compile NGINX yourself. Nginx v1.11.0 was used in the project. Download it from this link:

- [Nginx web server](http://nginx.org/) (v1.11.0);

TaLoS is used massively in this project and so it has to be setup before you continue with the project.

Follow the steps here to setup TaLoS

- [TaLoS](https://github.com/lsds/TaLoS/blob/master/README.md)

# How to start the program.
* First, check that the **Makefile** in the `nginx` source folder is correctly configured.
* If it is, go ahead to verify if the **Makefile** in the `objs` directory is also configured correctly.
* Next, go in to the **Makefiles** of both enclaves `nginx_sgx_bank/Enclave1` and `nginx_sgx_bank/Enclave2`.
* At the `configure` command during the installation of **TaLoS**, add `--add-module=${path to nginx_sgx_bank}` to the `configure` command.
* If everything is correctly configured, run a `make` command to compile the nginx server.
* Both enclaves would have to be compile by running `make` in the respective directories.
* A copy of a Makefile which compiles and starts the whole server will be in the `nginx_sgx_bank` directory. You can use it simplify starting the server. Also a copy of the Makefile in the `objs` directory will be provided to simplify the compilation of nginx. They are located in the `copies` directory in the `nginx_sgx_bank` directory.

# TODO 
Currently, the api for RSA decryption in the enclaves is not working properly, and it's a bit unstable.

Also, the JSON library (Jansson) cannot successfully handle UTF-8 strings passed from the web client. I had to encode the string in base64 and decode it into UTF-8 in the nginx module but the decoding is also not working properly, so it is very hard to send encrypted data to the enclaves.

This is a link to the web client:

- [Web Client](https://github.com/kbamponsem/sgx-bank-client.git)