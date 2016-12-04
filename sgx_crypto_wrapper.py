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

import unittest
import logging
from ctypes import cdll, CDLL, c_long, c_int, c_float, c_double, c_char_p, create_string_buffer, byref, c_voidp, c_uint8, c_uint32
import sys 
import os

class SGXCryptoWrapperError( Exception ):
	def __init__( self,  errCode ):
		msg = "SGX Error 0x%x" % errCode
		Exception.__init__( self, msg )
		self.errorCode = errCode

SGX_ECP256_KEY_SIZE     = 32
ECC256_PRIVATE_KEY_SIZE = SGX_ECP256_KEY_SIZE
ECC256_PUBLIC_KEY_SIZE  = 2 * SGX_ECP256_KEY_SIZE
ECC256_SHARED_KEY_SIZE  = SGX_ECP256_KEY_SIZE
SGX_CMAC_KEY_SIZE       = 16
EC_KEY_128_BIT_SIZE     = SGX_CMAC_KEY_SIZE
EC256_SIGNATURE_SIZE    = 2 * SGX_ECP256_KEY_SIZE
SGX_CMAC_MAC_SIZE       = 16
SGX_SHA256_HASH_SIZE    = 32

class SGXCryptoWrapper():
    def __init__( self, sharedObjectPath = './crypto_wrapper.so' ):
    	self.SetupLogger()
    	self.implementation = CDLL( sharedObjectPath )  

    def SetupLogger( self ):
        self.log = logging.getLogger( 'SGXCryptoWrapper' )
        self.log.setLevel(logging.DEBUG)

        formatter 	   = logging.Formatter('%(asctime)s %(name)-20s %(levelname)-10s %(message)s')
        consoleHandler = logging.StreamHandler()
        consoleHandler.setLevel(logging.DEBUG)
        consoleHandler.setFormatter(formatter)

        self.log.handlers = []
        self.log.addHandler(consoleHandler)	

    def ecc256_open_context(self):
        self.log.debug( "ecc256_open_context" )

        context = c_voidp()
        result  = self.implementation.sgx_ecc256_open_context( byref( context ) )

        self.VerifyResult( result )
        self.log.debug( "ecc256_open_context: context = 0x%x" % context.value )

        return context

    def ecc256_create_key_pair( self, context ):
        self.log.debug( "ecc256_create_key_pair" )
        privateKey = ( c_uint8 * ECC256_PRIVATE_KEY_SIZE )()
        publicKey  = ( c_uint8 * ECC256_PUBLIC_KEY_SIZE )()

        result = self.implementation.sgx_ecc256_create_key_pair( privateKey, publicKey, context)
        self.VerifyResult( result )

        return privateKey, publicKey

    def ecc256_close_context( self, context ):
        self.log.debug( "ecc256_close_context" )

        result = self.implementation.sgx_ecc256_close_context( context)
        self.VerifyResult( result )

    def ecc256_compute_shared_dhkey( self, context, privateKey, otherGuyPublicKey ):
        self.log.debug( "ecc256_compute_shared_dhkey" )

        privateKey_c        = ( c_uint8 * ECC256_PRIVATE_KEY_SIZE )()
        otherGuyPublicKey_c = ( c_uint8 * ECC256_PUBLIC_KEY_SIZE  )()
        sharedSecret        = ( c_uint8 * ECC256_SHARED_KEY_SIZE  )()

        for i in range( ECC256_PRIVATE_KEY_SIZE ):
            privateKey_c[ i ] = privateKey[ i ]

        for i in range( ECC256_PUBLIC_KEY_SIZE ):
            otherGuyPublicKey_c[ i ] = otherGuyPublicKey[ i ]

        result = self.implementation.sgx_ecc256_compute_shared_dhkey( privateKey_c, otherGuyPublicKey_c, sharedSecret, context)
        self.VerifyResult( result )

        return sharedSecret

    def CreateECC256_keyPair( self ):
        self.log.debug( "CreateECC256_keyPair" )
        context = self.ecc256_open_context()
        privateKey, publicKey = self.ecc256_create_key_pair( context )
        self.ecc256_close_context( context )

        return privateKey, publicKey

    def ComputeSharedSecret( self, privateKey, otherGuyPublicKey ):
        self.log.debug( "ComputeSharedSecret" )
        context = self.ecc256_open_context()
        sharedSecret = self.ecc256_compute_shared_dhkey( context, privateKey, otherGuyPublicKey )
        self.ecc256_close_context( context )        

        return sharedSecret

    def DeriveKey( self, masterSecret, nullTerminatedLabel_AsByteArray ):
        self.log.debug( "DeriveKey" )
        masterSecret_c = ( c_uint8 * ECC256_SHARED_KEY_SIZE  )()

        for i in range( ECC256_SHARED_KEY_SIZE ):
            masterSecret_c[ i ] = masterSecret[ i ]

        label_c    = c_char_p( nullTerminatedLabel_AsByteArray )
        label_size = c_uint32( len( nullTerminatedLabel_AsByteArray ) - 1 )
        derivedKey = ( c_uint8 * EC_KEY_128_BIT_SIZE )()

        result = self.implementation.derive_key( masterSecret_c, label_c, label_size, derivedKey )
        self.VerifyResult( result )

        return derivedKey

    def SignECDSA( self, dataToSign, signingKey ):
        self.log.debug( "SignECDSA" )
        dataToSign_c = ( c_uint8 * len( dataToSign )    )()
        signingKey_c = ( c_uint8 * len( signingKey )    )()
        signature    = ( c_uint8 * EC256_SIGNATURE_SIZE )() 

        dataSize = c_uint32( len( dataToSign )  )

        for i in range( len( dataToSign )  ):
            dataToSign_c[ i ] = dataToSign[ i ]

        for i in range( len( signingKey ) ):
            signingKey_c[ i ] = signingKey[ i ]

        context = self.ecc256_open_context()
        try:
            result = self.implementation.sgx_ecdsa_sign( dataToSign_c, dataSize, signingKey_c, signature, context )
            self.VerifyResult( result )
        finally:
            self.ecc256_close_context( context )  

        return signature

    def VerifyECDSASignature( self, signedData, signature, publicKey ):
        self.log.debug( "VerifyECDSASignature" )
        SGX_EC_VALID             = 0
        SGX_EC_INVALID_SIGNATURE = 17

        signedData_c = ( c_uint8 * len( signedData )   )()
        signature_c  = ( c_uint8 * len( signature )    )()
        publicKey_c  = ( c_uint8 * len( publicKey )    )()


        for i in range( len( signedData )  ):
            signedData_c[ i ] = signedData[ i ]

        for i in range( len( signature ) ):
            signature_c[ i ] = signature[ i ]

        for i in range( len( publicKey ) ):
            publicKey_c[ i ] = publicKey[ i ]

        signedDataSize     = c_uint32( len( signedData ) )
        verificationResult = c_uint8( SGX_EC_INVALID_SIGNATURE )

        context = self.ecc256_open_context()
        try:
            result = self.implementation.sgx_ecdsa_verify(  signedData_c, 
                                                            signedDataSize, 
                                                            publicKey_c, 
                                                            signature_c, 
                                                            byref( verificationResult ), 
                                                            context )
            self.VerifyResult( result )
        finally:
            self.ecc256_close_context( context )  

        return verificationResult.value == SGX_EC_VALID

    def Rijndael128_CMAC( self, dataToMAC, macKey ):
        self.log.debug( "Rijndael128_CMAC" )
        dataToMAC_c = ( c_uint8 * len( dataToMAC )  )()
        macKey_c    = ( c_uint8 * len( macKey )     )()
        mac         = ( c_uint8 * SGX_CMAC_MAC_SIZE )()

        dataSize = c_uint32( len( dataToMAC )  )

        for i in range( len( dataToMAC_c )  ):
            dataToMAC_c[ i ] = dataToMAC[ i ]

        for i in range( len( macKey_c ) ):
            macKey_c[ i ] = macKey[ i ]

        context = self.ecc256_open_context()
        try:
            result = self.implementation.sgx_rijndael128_cmac_msg( macKey_c, dataToMAC_c, dataSize, mac )
            self.VerifyResult( result )
        finally:
            self.ecc256_close_context( context )  

        return mac

    def SHA256( self, dataToDigest ):
        self.log.debug( "SHA256" )

        dataToDigest_c = ( c_uint8 * len( dataToDigest )  )()
        digest         = ( c_uint8 * SGX_SHA256_HASH_SIZE )()

        dataSize = c_uint32( len( dataToDigest )  )

        for i in range( len( dataToDigest )  ):
            dataToDigest_c[ i ] = dataToDigest[ i ]

        result = self.implementation.sgx_sha256_msg( dataToDigest_c, dataSize, digest )
        self.VerifyResult( result )

        return bytearray( digest )

    def VerifyResult( self, result ):
        if result == SGXStatus.SGX_SUCCESS:
        	return
        else:
        	raise SGXCryptoWrapperError( result )

class SGXStatus:
    SGX_SUCCESS                  = 0x0000

    SGX_ERROR_UNEXPECTED         = 0x0001      # /* Unexpected error */
    SGX_ERROR_INVALID_PARAMETER  = 0x0002      # /* The parameter is incorrect */
    SGX_ERROR_OUT_OF_MEMORY      = 0x0003      # /* Not enough memory is available to complete this operation */
    SGX_ERROR_ENCLAVE_LOST       = 0x0004      # /* Enclave lost after power transition or used in child process created by linux:fork() */
    SGX_ERROR_INVALID_STATE      = 0x0005      # /* SGX API is invoked in incorrect order or state */

    SGX_ERROR_INVALID_FUNCTION   = 0x1001      # /* The ecall/ocall index is invalid */
    SGX_ERROR_OUT_OF_TCS         = 0x1003      # /* The enclave is out of TCS */
    SGX_ERROR_ENCLAVE_CRASHED    = 0x1006      # /* The enclave is crashed */
    SGX_ERROR_ECALL_NOT_ALLOWED  = 0x1007      # /* The ECALL is not allowed at this time, e.g. ecall is blocked by the dynamic entry table, or nested ecall is not allowed during initialization */
    SGX_ERROR_OCALL_NOT_ALLOWED  = 0x1008      # /* The OCALL is not allowed at this time, e.g. ocall is not allowed during exception handling */
    SGX_ERROR_STACK_OVERRUN      = 0x1009      # /* The enclave is running out of stack */

    SGX_ERROR_UNDEFINED_SYMBOL   = 0x2000      # /* The enclave image has undefined symbol. */
    SGX_ERROR_INVALID_ENCLAVE    = 0x2001      # /* The enclave image is not correct. */
    SGX_ERROR_INVALID_ENCLAVE_ID = 0x2002      # /* The enclave id is invalid */
    SGX_ERROR_INVALID_SIGNATURE  = 0x2003      # /* The signature is invalid */
    SGX_ERROR_NDEBUG_ENCLAVE     = 0x2004      # /* The enclave is signed as product enclave, and can not be created as debuggable enclave. */
    SGX_ERROR_OUT_OF_EPC         = 0x2005      # /* Not enough EPC is available to load the enclave */
    SGX_ERROR_NO_DEVICE          = 0x2006      # /* Can't open SGX device */
    SGX_ERROR_MEMORY_MAP_CONFLICT= 0x2007      # /* Page mapping failed in driver */
    SGX_ERROR_INVALID_METADATA   = 0x2009      # /* The metadata is incorrect. */
    SGX_ERROR_DEVICE_BUSY        = 0x200c      # /* Device is busy, mostly EINIT failed. */
    SGX_ERROR_INVALID_VERSION    = 0x200d      # /* Metadata version is inconsistent between uRTS and sgx_sign or uRTS is incompatible with current platform. */
    SGX_ERROR_MODE_INCOMPATIBLE  = 0x200e      # /* The target enclave 32/64 bit mode or sim/hw mode is incompatible with the mode of current uRTS. */
    SGX_ERROR_ENCLAVE_FILE_ACCESS = 0x200f     # /* Can't open enclave file. */
    SGX_ERROR_INVALID_MISC        = 0x2010     # /* The MiscSelct/MiscMask settings are not correct.*/

    SGX_ERROR_MAC_MISMATCH       = 0x3001      # /* Indicates verification error for reports, sealed datas, etc */
    SGX_ERROR_INVALID_ATTRIBUTE  = 0x3002      # /* The enclave is not authorized */
    SGX_ERROR_INVALID_CPUSVN     = 0x3003      # /* The cpu svn is beyond platform's cpu svn value */
    SGX_ERROR_INVALID_ISVSVN     = 0x3004      # /* The isv svn is greater than the enclave's isv svn */
    SGX_ERROR_INVALID_KEYNAME    = 0x3005      # /* The key name is an unsupported value */

    SGX_ERROR_SERVICE_UNAVAILABLE       = 0x4001   # /* Indicates aesm didn't response or the requested service is not supported */
    SGX_ERROR_SERVICE_TIMEOUT           = 0x4002   # /* The request to aesm time out */
    SGX_ERROR_AE_INVALID_EPIDBLOB       = 0x4003   # /* Indicates epid blob verification error */
    SGX_ERROR_SERVICE_INVALID_PRIVILEGE = 0x4004   # /* Enclave has no privilege to get launch token */
    SGX_ERROR_EPID_MEMBER_REVOKED       = 0x4005   # /* The EPID group membership is revoked. */
    SGX_ERROR_UPDATE_NEEDED             = 0x4006   # /* SGX needs to be updated */
    SGX_ERROR_NETWORK_FAILURE           = 0x4007   # /* Network connecting or proxy setting issue is encountered */
    SGX_ERROR_AE_SESSION_INVALID        = 0x4008   # /* Session is invalid or ended by server */
    SGX_ERROR_BUSY                      = 0x400a   # /* The requested service is temporarily not availabe */
    SGX_ERROR_MC_NOT_FOUND              = 0x400c   # /* The Monotonic Counter doesn't exist or has been invalided */
    SGX_ERROR_MC_NO_ACCESS_RIGHT        = 0x400d   # /* Caller doesn't have the access right to specified VMC */
    SGX_ERROR_MC_USED_UP                = 0x400e   # /* Monotonic counters are used out */
    SGX_ERROR_MC_OVER_QUOTA             = 0x400f   # /* Monotonic counters exceeds quota limitation */
    SGX_ERROR_KDF_MISMATCH              = 0x4011   # /* Key derivation function doesn't match during key exchange */

class TestSGXCryptoWrapper(unittest.TestCase):
    def setUp(self):
        print('In setUp()')
        self.cryptoWrapper = SGXCryptoWrapper( './crypto_wrapper.so' )

    def tearDown(self):
        print('In tearDown()')

    def test_constructor( self ):
        pass

    def test_createKeyPair( self ):
        privateKey, publicKey = self.cryptoWrapper.CreateECC256_keyPair()

        print( "Private key:")
        for i in range( ECC256_PRIVATE_KEY_SIZE ):
            sys.stdout.write( "0x%02x, " % privateKey[ i ] )
            if ( i + 1 ) % 8 == 0:
                print( "" )

        print( "My public key:")
        for i in range( ECC256_PUBLIC_KEY_SIZE ):
            sys.stdout.write( "0x%02x, " % publicKey[ i ] )
            if ( i + 1 ) % 8 == 0:
                print( "" )

    def test_computeSharedSecret( self ):
        privateKey_1, publicKey_1 = self.cryptoWrapper.CreateECC256_keyPair()
        privateKey_2, publicKey_2 = self.cryptoWrapper.CreateECC256_keyPair()
        
        sharedSecret_1            = self.cryptoWrapper.ComputeSharedSecret( privateKey_1, publicKey_2 )
        sharedSecret_2            = self.cryptoWrapper.ComputeSharedSecret( privateKey_2, publicKey_1 )

        print( "Private key 1:")
        for i in range( ECC256_PRIVATE_KEY_SIZE ):
            sys.stdout.write( "0x%02x, " % privateKey_1[ i ] )
            if ( i + 1 ) % 8 == 0:
                print( "" )

        print( "Ppublic key 1:")
        for i in range( ECC256_PUBLIC_KEY_SIZE ):
            sys.stdout.write( "0x%02x, " % publicKey_1[ i ] )
            if ( i + 1 ) % 8 == 0:
                print( "" )

        print( "Private key 2:")
        for i in range( ECC256_PRIVATE_KEY_SIZE ):
            sys.stdout.write( "0x%02x, " % privateKey_2[ i ] )
            if ( i + 1 ) % 8 == 0:
                print( "" )

        print( "Ppublic key 2:")
        for i in range( ECC256_PUBLIC_KEY_SIZE ):
            sys.stdout.write( "0x%02x, " % publicKey_2[ i ] )
            if ( i + 1 ) % 8 == 0:
                print( "" )

        print( "shared secret 1:")
        for i in range( ECC256_SHARED_KEY_SIZE ):
            sys.stdout.write( "0x%02x, " % sharedSecret_1[ i ] )
            if ( i + 1 ) % 8 == 0:
                print( "" )

        print( "shared secret 2:")
        for i in range( ECC256_SHARED_KEY_SIZE ):
            sys.stdout.write( "0x%02x, " % sharedSecret_2[ i ] )
            if ( i + 1 ) % 8 == 0:
                print( "" )

        for i in range( ECC256_SHARED_KEY_SIZE ):
            self.assertTrue(  sharedSecret_1[ i ] == sharedSecret_2[ i ], 
                                msg = "At byte %d: 0x%02x != 0x%02x" % ( i, sharedSecret_1[ i ] , sharedSecret_2[ i ] ) )

    def test_signECDSA( self ):
        privateKey = \
        [ 0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce, 
        0x3b, 0x66, 0xde, 0x11, 0x43, 0x9c, 0x87, 0xec,
        0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6, 0xae, 0xea,
        0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01 ]

        publicKey = \
        [
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38,
    
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06,
        ]
    
        dataToSign = bytearray( os.urandom( 2000 ) )
        signature  = self.cryptoWrapper.SignECDSA( dataToSign, privateKey )
        self.assertTrue( self.cryptoWrapper.VerifyECDSASignature( dataToSign, signature, publicKey ) )

        dataToSign[ 20 ] ^= 1
        self.assertFalse( self.cryptoWrapper.VerifyECDSASignature( dataToSign, signature, publicKey ) )


if __name__ == '__main__':
	unittest.main()























