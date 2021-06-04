#
# Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1
CC=clang
C++=clang++
PROJ_DIR ?= /home/kwabena/TaLoS/src/nginx-1.11.0/nginx_sgx_bank
ENCLAVES_DIR ?= Enclaves_u

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2
endif

######## App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

C_FLAGS := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes -I$(SGX_SDK)/include

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        C_FLAGS += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        C_FLAGS += -DNDEBUG -DEDEBUG -UDEBUG
else
        C_FLAGS += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread 

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

App_Name := app

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_Cpp_Files := Enclave/Enclave.cpp
Enclave_Include_Paths := -IEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths) -I/usr/include
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++03 -nostdinc++

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=Enclave/Enclave.lds

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := Enclave/Enclave.config.xml

######## Enclaves Objects ########
untrusted:
	@echo "Compiling untrusted code."

	@mkdir -p $(PROJ_DIR)/$(ENCLAVES_DIR)/Enclave2/Untrusted
	@cp Enclave/Enclave.edl $(PROJ_DIR)/$(ENCLAVES_DIR)/Enclave2
	@cd $(PROJ_DIR)/$(ENCLAVES_DIR)/Enclave2/Untrusted && $(SGX_EDGER8R) --untrusted ../Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include && rm ../Enclave.edl

	@$(CC) $(C_FLAGS) -c $(PROJ_DIR)/$(ENCLAVES_DIR)/Enclave2/Untrusted/Enclave_u.c -o $(PROJ_DIR)/$(ENCLAVES_DIR)/Enclave2/Untrusted/Enclave_u.o
	@echo "CC   <=  $(PROJ_DIR)/$(ENCLAVES_DIR)/Enclave2/Untrusted/Enclave_u.c"


######## Enclave Objects ########
trusted:
	@echo "Compiling trusted code."
	@cp -r Enclave $(PROJ_DIR)/$(ENCLAVES_DIR)/Enclave2
	@cd $(PROJ_DIR)/$(ENCLAVES_DIR)/Enclave2/Enclave && $(SGX_EDGER8R) --trusted Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@cd -
	@echo "GEN  =>  $(PROJ_DIR)/$(ENCLAVES_DIR)/Enclave2/Enclave/Enclave_t.c"

	@$(CC) $(Enclave_C_Flags) -c $(PROJ_DIR)/$(ENCLAVES_DIR)/Enclave2/Enclave/Enclave_t.c -o $(PROJ_DIR)/$(ENCLAVES_DIR)/Enclave2/Enclave/Enclave_t.o
	@echo "CC   <=  $(PROJ_DIR)/$(ENCLAVES_DIR)/Enclave2/Enclave/Enclave_t.c"

	@$(CXX) $(Enclave_Cpp_Flags) -c $(PROJ_DIR)/$(ENCLAVES_DIR)/Enclave2/Enclave/Enclave.cpp -o $(PROJ_DIR)/$(ENCLAVES_DIR)/Enclave2/Enclave/Enclave.o
	@echo "CXX  <=  $(PROJ_DIR)/$(ENCLAVES_DIR)/Enclave2/Enclave/Enclave.cpp"

	@$(CXX) $(PROJ_DIR)/$(ENCLAVES_DIR)/Enclave2/Enclave/Enclave_t.o $(PROJ_DIR)/$(ENCLAVES_DIR)/Enclave2/Enclave/Enclave.o -o $(PROJ_DIR)/$(ENCLAVES_DIR)/Enclave2/$(Enclave_Name) $(Enclave_Link_Flags)
	@echo "LINK =>  $(PROJ_DIR)/$(ENCLAVES_DIR)/Enclave2/$(Enclave_Name)"

 
	@$(SGX_ENCLAVE_SIGNER) sign -key $(PROJ_DIR)/$(ENCLAVES_DIR)/Enclave2/Enclave/Enclave_private.pem \
	-enclave $(PROJ_DIR)/$(ENCLAVES_DIR)/Enclave2/$(Enclave_Name) \
	-out $(PROJ_DIR)/$(ENCLAVES_DIR)/Enclave2/$(Signed_Enclave_Name) \
	-config $(PROJ_DIR)/$(ENCLAVES_DIR)/Enclave2/$(Enclave_Config_File)

	@echo "SIGN =>  $(PROJ_DIR)/$(ENCLAVES_DIR)/Enclave2/$(Signed_Enclave_Name)"

	@rm -rf $(PROJ_DIR)/$(ENCLAVES_DIR)/Enclave2/Enclave

nginx_sgx: clean untrusted trusted

.PHONY: clean

clean:
	@rm -f .config_* $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) App/Enclave_u.* $(Enclave_Cpp_Objects) Enclave/Enclave_t.*
	@rm -rf $(PROJ_DIR)/$(ENCLAVES_DIR)/Enclave2/*
