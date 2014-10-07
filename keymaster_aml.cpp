/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <errno.h>
#include <string.h>
#include <stdint.h>

#include <keystore/keystore.h>

#include <hardware/hardware.h>
#include <hardware/keymaster.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include <utils/UniquePtr.h>

// For debugging
//#define LOG_NDEBUG 0

#define LOG_TAG "AmlKeyMaster"
#include <cutils/log.h>

#include <keymaster/softkeymaster.h>

#ifdef USE_SECUREOS
#include <keymaster_secure_api.h>

struct aml_keyblob{
	unsigned char* handle;
	size_t handle_length;
};
typedef struct aml_keyblob aml_keyblob_t;
typedef UniquePtr<aml_keyblob_t> Unique_aml_keyblob_t;

static int aml_wrap_key(uint8_t* handle, const size_t handle_length, uint8_t** keyBlob, size_t* keyBlobLength) {
    Unique_aml_keyblob_t derData(new(aml_keyblob_t));
	if (derData.get() == NULL){
        ALOGE("Error: could not allocate memory for key blob");
		return -1;
	}

	derData.get()->handle = handle;
	derData.get()->handle_length = handle_length;

    *keyBlobLength = sizeof(aml_keyblob_t);
    *keyBlob = (uint8_t*)derData.release();

	return 0;
}

static int aml_unwrap_key(const uint8_t* key_blob, const size_t, uint8_t** handle, size_t* handle_length) 
{
	const aml_keyblob_t* temp = (const aml_keyblob_t*)key_blob;

	// Sanity check
	if (NULL == key_blob){
        ALOGE("Error: invalid input.");
		return -1;
	}

	*handle = temp->handle;
	*handle_length = temp->handle_length;

	return 0;
}

__attribute__ ((visibility ("default")))
int aml_delete_keypair(const keymaster_device_t* dev,
        const uint8_t* key_blob, const size_t key_blob_length) {
	
	uint8_t* handle = NULL;
	size_t handle_length = 0;

    if (NULL == key_blob || 0 == key_blob_length || NULL == dev) {
        ALOGW("Error: key_blob == NULL");
        return -1;
    }

    aml_unwrap_key(key_blob, key_blob_length, &handle, &handle_length);

	if (KM_secure_delete_keypair(dev, handle, handle_length) < 0){
        ALOGE("Error: Fail to issue KM_secure_delete_keypair");
        return -1;
	}
	
	return 0;
}

#endif
__attribute__ ((visibility ("default")))
int aml_generate_keypair(const keymaster_device_t* dev,
        const keymaster_keypair_t key_type, const void* key_params,
		uint8_t** key_blob, size_t* key_blob_length) {

	ALOGE("=== aml_generate_keypair ====");
	if (key_params == NULL) {
		ALOGE("Error: key_params == null");
		return -1;
	} 

	if (key_blob == NULL || key_blob_length == NULL) {
		ALOGE("Error: output buffer is null.");
		return -1;
	} 
#ifdef USE_SECUREOS
	uint8_t* key_handle = NULL;
	size_t key_handle_length = 0;

	if (KM_secure_generate_keypair(dev, key_type, key_params, &key_handle, &key_handle_length) < 0){
	    ALOGE("Error: KM_secure_generate_keypair fails.");
		return -1;
	}
	aml_wrap_key(key_handle, key_handle_length, key_blob, key_blob_length);
#else
    if (openssl_generate_keypair(dev, key_type, key_params, key_blob, key_blob_length) < 0){
        ALOGE("Error: openssl_generate_keypair fails");
        return -1;
	}
#endif
    return 0;
}

__attribute__ ((visibility ("default")))
int aml_import_keypair(const keymaster_device_t* dev,
        const uint8_t* key, const size_t key_length,
        uint8_t** key_blob, size_t* key_blob_length) {

	// Sanity check
    if (key == NULL) {
        ALOGE("Error: input key == NULL");
        return -1;
    } else if (key_blob == NULL || key_blob_length == NULL) {
        ALOGE("Error: output key blob or length == NULL");
        return -1;
    }

#ifdef USE_SECUREOS
	uint8_t* key_handle = NULL;
	size_t key_handle_length = 0;

    ALOGE("key length = %d", key_length);
    if (KM_secure_import_keypair(dev, key, key_length, &key_handle, &key_handle_length) < 0){
        ALOGE("Error: KM_secure_import_keypair fails");
        return -1;
    }
	aml_wrap_key(key_handle, key_handle_length, key_blob, key_blob_length);
#else
    if (openssl_import_keypair(dev, key, key_length, key_blob, key_blob_length) < 0){
        ALOGE("Error: openssl_import_keypair fails");
        return -1;
	}
#endif
	return 0;
}

__attribute__ ((visibility ("default")))
int aml_get_keypair_public(const struct keymaster_device* dev,
        const uint8_t* key_blob, const size_t key_blob_length,
        uint8_t** x509_data, size_t* x509_data_length) {

	int retVal = -1;

	ALOGE("=== aml_get_keypair_public ====");
    if (x509_data == NULL || x509_data_length == NULL) {
        ALOGE("Error: output public key buffer == NULL");
        return -1;
    }

#ifdef USE_SECUREOS
	uint8_t* handle = NULL;
	size_t handle_length = 0;

    aml_unwrap_key(key_blob, key_blob_length, &handle, &handle_length);
    retVal = KM_secure_get_keypair_public(dev, handle, handle_length, x509_data, x509_data_length);
	if (retVal < 0){
        ALOGE("Error: KM_secure_get_keypair_public fails.");
	}
#else
    retVal = openssl_get_keypair_public(dev, key_blob, key_blob_length, x509_data, x509_data_length);
	if (retVal < 0){
        ALOGE("Error: openssl_get_keypair_public fails.");
	}
#endif

    return retVal;
}

__attribute__ ((visibility ("default")))
int aml_sign_data(const keymaster_device_t* dev,
        const void* params,
        const uint8_t* key_blob, const size_t key_blob_length,
        const uint8_t* data, const size_t data_length,
        uint8_t** signed_data, size_t* signed_data_length) {

	int retVal = -1;

    if (data == NULL) {
        ALOGW("input data to sign == NULL");
        return retVal;
    } else if (signed_data == NULL || signed_data_length == NULL) {
        ALOGW("output signature buffer == NULL");
        return retVal;
    }

#ifdef USE_SECUREOS
	uint8_t* handle = NULL;
	size_t handle_length = 0;
    int key_type;

    aml_unwrap_key(key_blob, key_blob_length, &handle, &handle_length);
    key_type = KM_secure_get_key_type(handle);

    retVal = KM_secure_sign_data(dev, (keymaster_keypair_t)key_type, 
			                          params,
			                          handle, handle_length,
									  data, data_length,
									  signed_data, signed_data_length);
	if (retVal < 0){
        ALOGE("Error: KM_secure_sign_data fails.");
	}
#else
    retVal = openssl_sign_data(dev, params, key_blob, key_blob_length, data, data_length, signed_data, signed_data_length);
	if (retVal < 0){
        ALOGE("Error: openssl_sign_data fails.");
	}
#endif
	return retVal;
}

__attribute__ ((visibility ("default")))
int aml_verify_data(const keymaster_device_t* dev,
        const void* params,
        const uint8_t* key_blob, const size_t key_blob_length,
        const uint8_t* signed_data, const size_t signed_data_length,
        const uint8_t* signature, const size_t signature_length) {
	int retVal = -1;

    if (signed_data == NULL || signature == NULL) {
        ALOGE("Error: data or signature buffers == NULL");
        return retVal;
    }
#ifdef USE_SECUREOS
	uint8_t* handle = NULL;
	size_t handle_length = 0;
	int key_type = -1;

    aml_unwrap_key(key_blob, key_blob_length, &handle, &handle_length);
    key_type = KM_secure_get_key_type(handle);

    retVal = KM_secure_verify_data(dev, (keymaster_keypair_t)key_type, 
			                          params,
			                          handle, handle_length,
									  signed_data, signed_data_length,
									  signature, signature_length);
	if (retVal < 0){
        ALOGE("Error: KM_secure_verify_data fails.");
	}
#else
    retVal = openssl_verify_data(dev, params, key_blob, key_blob_length, signed_data, signed_data_length, signature, signature_length);
	if (retVal < 0){
        ALOGE("Error: openssl_verify_data fails.");
	}
#endif
	return retVal;
}

__attribute__ ((visibility ("default")))
int aml_terminate() {
#ifdef USE_SECUREOS
    return KM_Secure_Terminate();
#else
    return 0;
#endif
}
