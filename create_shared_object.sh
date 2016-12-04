#!/bin/bash

# Author: Ofir Weisse, mail: oweisse (at) umich.edu, www.ofirweisse.com
#
# MIT License
#
# Copyright (c) 2016 oweisse
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

set -v
set -e

SGX_SOURCE_PATH=/home/sgx/github/intel-linux-sgx_2/linux-sgx

g++ -c -fPIC sgx_memset_s.cpp 
g++ -c -fPIC sgx_read_rand.cpp -I/opt/intel/sgxsdk/include/ -I$SGX_SOURCE_PATH/common/inc/internal/ -Irdrand/
g++ -c -fPIC ecp.cpp -I/opt/intel/sgxsdk/include/ -I$SGX_SOURCE_PATH/common/inc/internal/
gcc -c -fPIC consttime_memequal.c

cd rdrand; make; cd -

cd tlibcrypto
g++ -c init_crypto_lib.cpp -fPIC -I$SGX_SOURCE_PATH/common/inc/internal -I$SGX_SOURCE_PATH/common/inc -I$SGX_SOURCE_PATH/common/inc/tlibc -I$SGX_SOURCE_PATH/external/crypto_px/include
g++ -c sgx_aes_ctr.cpp -fPIC -I$SGX_SOURCE_PATH/common/inc/internal -I$SGX_SOURCE_PATH/common/inc -I$SGX_SOURCE_PATH/common/inc/tlibc -I$SGX_SOURCE_PATH/external/crypto_px/include
g++ -c sgx_aes_gcm.cpp -fPIC -I$SGX_SOURCE_PATH/common/inc/internal -I$SGX_SOURCE_PATH/common/inc -I$SGX_SOURCE_PATH/common/inc/tlibc -I$SGX_SOURCE_PATH/external/crypto_px/include
g++ -c sgx_cmac128.cpp -fPIC -I$SGX_SOURCE_PATH/common/inc/internal -I$SGX_SOURCE_PATH/common/inc -I$SGX_SOURCE_PATH/common/inc/tlibc -I$SGX_SOURCE_PATH/external/crypto_px/include
g++ -c sgx_ecc256.cpp -fPIC -I$SGX_SOURCE_PATH/common/inc/internal -I$SGX_SOURCE_PATH/common/inc -I$SGX_SOURCE_PATH/common/inc/tlibc -I$SGX_SOURCE_PATH/external/crypto_px/include
g++ -c sgx_ecc256_common.cpp -fPIC -I$SGX_SOURCE_PATH/common/inc/internal -I$SGX_SOURCE_PATH/common/inc -I$SGX_SOURCE_PATH/common/inc/tlibc -I$SGX_SOURCE_PATH/external/crypto_px/include
g++ -c sgx_ecc256_ecdsa.cpp -fPIC -I$SGX_SOURCE_PATH/common/inc/internal -I$SGX_SOURCE_PATH/common/inc -I$SGX_SOURCE_PATH/common/inc/tlibc -I$SGX_SOURCE_PATH/external/crypto_px/include
g++ -c sgx_sha256.cpp -fPIC -I$SGX_SOURCE_PATH/common/inc/internal -I$SGX_SOURCE_PATH/common/inc -I$SGX_SOURCE_PATH/common/inc/tlibc -I$SGX_SOURCE_PATH/external/crypto_px/include
g++ -c sgx_sha256_msg.cpp -fPIC -I$SGX_SOURCE_PATH/common/inc/internal -I$SGX_SOURCE_PATH/common/inc -I$SGX_SOURCE_PATH/common/inc/tlibc -I$SGX_SOURCE_PATH/external/crypto_px/include
g++ -c tcrypto_version.cpp -fPIC -I$SGX_SOURCE_PATH/common/inc/internal -I$SGX_SOURCE_PATH/common/inc -I$SGX_SOURCE_PATH/common/inc/tlibc -I$SGX_SOURCE_PATH/external/crypto_px/include
cd -
 
cd $SGX_SOURCE_PATH/external/crypto_px 
make 
cd -
g++   -shared	-Wl,--whole-archive \
				sgx_memset_s.o \
				consttime_memequal.o  \
				sgx_read_rand.o \
				rdrand/rdrand.o  \
				ecp.o 							\
				./tlibcrypto/init_crypto_lib.o \
				./tlibcrypto/sgx_aes_ctr.o \
				./tlibcrypto/sgx_aes_gcm.o \
				./tlibcrypto/sgx_cmac128.o \
				./tlibcrypto/sgx_ecc256.o \
				./tlibcrypto/sgx_ecc256_common.o \
				./tlibcrypto/sgx_ecc256_ecdsa.o \
				./tlibcrypto/sgx_sha256.o \
				./tlibcrypto/sgx_sha256_msg.o \
				./tlibcrypto/tcrypto_version.o \
				$SGX_SOURCE_PATH/external/crypto_px/libcrypto_px.a \
				-Wl,--no-whole-archive -o crypto_wrapper.so
				

