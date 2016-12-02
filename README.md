# Python SGX Crypto Wrapper 

A Python wrapper for sgx_tcrypto library. The "sample_libcrypto" in SGX sources is marked not for production use, but the crypto code used inside the secure enclaves and the trusted libraries is golden (and licenced for re-use). The wrapped C++ code uses the production IPP crypto libraraies. Be aware that when using python scraping secrets from memory is not trivial.

This project contains files from different sources, see the license header in each file. 

The main file is `sgx_crypto_wrapper.py`. It wraps the shared object `crypto_wrapper.so`, which can be rebuilt by running `create_shared_object.sh`.

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
IMPORTANT: This is how the crypto library gets its enropy to create random key. If I were you I would make sure it's doing what you think it's doing..
This is basically a copy of `linux-sgx/external/rdrand/src` directory, with the exception of copying `linux-sgx/external/rdrand/rdrand.h` infto the `src` folder. This was done because the external h file uses `extern "C"` tricks to make sure function names are not mangled. 


