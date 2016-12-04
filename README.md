# Python SGX Crypto Wrapper 

A Python wrapper for sgx_tlibcrypto library. While the "sample_libcrypto" in SGX sources is marked not for production use, the crypto code used inside the secure enclaves and the trusted libraries is golden (and licenced for re-use). The wrapped C++ code uses the production IPP crypto libraraies. Be aware that when using python scraping secrets from memory is not trivial.

This project contains files from different sources, see the license header in each file. 

The main file is `sgx_crypto_wrapper.py`. It wraps the shared object `crypto_wrapper.so`, which can be rebuilt by running `create_shared_object.sh`. Runing 
```
python3 sgx_crypto_wrapper.py
```
run some non-axaustive unit tests. Look at the tests to figure out how to use this module. Tested with Python 3.5.2.

## Dependencies
### 1. The SGX SDK source code for Linux, which can be cloned by:
```
cd /my/folder/
git clone https://github.com/01org/linux-sgx
```
Make sure to update the `SGX_SOURCE_PATH` variable in `create_shared_object.sh`:
```
SGX_SOURCE_PATH=/my/folder/linux-sgx
```

### 2. RDRAND implementation, in `rdrand` folder. 
IMPORTANT: This is how the crypto library gets its enropy to create random keys. If I were you I would make sure it's doing what you think it's doing..
This is basically a copy of `linux-sgx/external/rdrand/src` directory, with the exception of copying `linux-sgx/external/rdrand/rdrand.h` infto the `src` folder. This was done because the external h file uses `extern "C"` tricks to make sure function names are not mangled. 

### 3. The SGX crypto library tlibcrypto
Copied from `linux-sgx/sdk/tlibcrypto`. The library is in essence a wrapper for Intel's IPP crypto library. They are recompiled here to allow dynamically exporting of the function in a shared object.

### 4. Intel's IPP crypto library
Found at `linux-sgx/external/crypto_px/`. The build script `create_shared_object.sh` runs the Makefile in the sources directory to create the static library `linux-sgx/external/crypto_px/libcrypto_px.a`. This static library is then linked into `crypto_wrapper.so`.
