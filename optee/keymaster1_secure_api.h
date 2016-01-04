#ifndef __KEYMASTER1_SECURE_API_H__
#define __KEYMASTER1_SECURE_API_H__

#ifdef __cplusplus
extern "C" {
#endif
#include <tee_api_types.h>
#include <utee_defines.h>
#include <tee_client_api.h>
#include "keymaster_ca.h"
#ifdef __cplusplus
}
#endif

#include <iostream>
#include <keymaster/authorization_set.h>
#include <hardware/keymaster0.h>
#include <hardware/keymaster1.h>
#include <keymaster/android_keymaster_utils.h>
#include "aml_keymaster_context.h"
using namespace keymaster;

int KM_Secure_Initialize(void);
int KM_Secure_Terminate(void);
int KM_secure_import_keypair(const keymaster1_device_t *dev,
        const uint8_t *key,
        const size_t key_bin_len,
        aml_keyblob_t *aml_key);

keymaster_error_t KM1_delete_key(const uint8_t *handle, uint32_t len);

keymaster_error_t KM1_load_key(TEE_ObjectHandle *keyobj,
		const uint8_t *handle, uint32_t len);

int KM_secure_query_key_existence(const keymaster1_device_t *dev,
        const TEE_ObjectHandle handle);
/* keymaster1 APIs */
keymaster_error_t KM1_secure_generate_key(const AuthorizationSet& key_description,
        aml_keyblob_t* aml_key,
        KeymasterKeyBlob *key_blob,
        AuthorizationSet *hw_enforced,
        AuthorizationSet *sw_enforced);

keymaster_error_t KM1_secure_begin(
        TEE_ObjectHandle obj,
        keymaster_algorithm_t android_algo,
        keymaster_purpose_t purpose,
        keymaster_digest_t digest, keymaster_padding_t padding,
        uint32_t optee_obj_len,
        TEE_OperationHandle* op_handle);

keymaster_error_t KM1_digest_init(keymaster_algorithm_t android_algo,
        uint32_t key_len,
        keymaster_digest_t digest,
        keymaster_padding_t padding,
        TEE_OperationHandle* digest_op);

keymaster_error_t KM1_digest_update(TEE_OperationHandle digest_op,
        const void* chunk,
        size_t chunk_len);

keymaster_error_t KM1_digest_final(TEE_OperationHandle digest_op,
        const void* chunk, size_t chunk_len,
        void* hash, size_t* hash_len);

keymaster_error_t KM1_allocate_operation(
        TEE_ObjectHandle key, uint32_t key_len,
        keymaster_algorithm_t android_algo,
        keymaster_purpose_t purpose,
        keymaster_digest_t digest_t, keymaster_padding_t padding_t,
        keymaster_block_mode_t block_mode,
        TEE_OperationHandle *operation,
        TEE_OperationMode* operation_mode);

keymaster_error_t KM1_asymmetric_sign_with_handle(
        TEE_OperationHandle op, TEE_OperationMode op_mode,
        const uint8_t* digest, const size_t digest_len,
        uint8_t* sig, size_t* sig_len);

keymaster_error_t KM1_asymmetric_verify_with_handle(
        TEE_OperationHandle op, TEE_OperationMode op_mode,
        const uint8_t* digest, const size_t digest_len,
        const uint8_t* sig, const size_t sig_len);

keymaster_error_t KM1_asymmetric_en_de_crypt_with_handle(
			TEE_OperationHandle op, TEE_OperationMode op_mode,
			const uint8_t* digest, const size_t digest_len,
			uint8_t* sig, size_t* sig_len);

keymaster_error_t KM1_import_symmetric_key(
        keymaster_algorithm_t algorithm,
        const AuthorizationSet& key_description,
        const uint8_t* key, const size_t key_len,
        aml_keyblob_t* aml_key);

keymaster_error_t KM1_cipher_init(const TEE_OperationHandle op,
                                  const void *iv, const size_t iv_len);

keymaster_error_t KM1_cipher_update(TEE_OperationHandle oph,
        const void *src, size_t src_len,
        void *dst, size_t *dst_len, const uint32_t need_buffering);

keymaster_error_t KM1_cipher_do_final(TEE_OperationHandle oph,
        const void *src, size_t src_len,
        void *dst, size_t *dst_len);

keymaster_error_t KM1_hmac_keyblob_init(keymaster_algorithm_t android_algo,
        keymaster_digest_t digest,
        TEE_OperationHandle* operation);

keymaster_error_t KM1_hmac_init(TEE_ObjectHandle key,
        uint32_t key_len,
        keymaster_algorithm_t android_algo,
        keymaster_digest_t digest,
        TEE_OperationHandle* operation);

keymaster_error_t KM1_hmac_update(TEE_OperationHandle digest_op,
        const void* chunk,
        size_t chunk_len);

keymaster_error_t KM1_hmac_final(TEE_OperationHandle hmac_op,
        const void* chunk, size_t chunk_len,
        void* hash, size_t* hash_len);

keymaster_error_t KM1_hmac_final_compare(TEE_OperationHandle hmac_op,
        const void* chunk, size_t chunk_len,
        const void* hash, size_t hash_len);

keymaster_error_t KM1_export_key(const uint8_t *id, uint32_t id_len,
		uint32_t obj_type, uint32_t key_len,
		uint8_t** x509_data, size_t* x509_data_len);

keymaster_error_t KM1_ae_init(const TEE_OperationHandle op,
                              const void *nonce, size_t nonce_len,
                              size_t tag_len, size_t aad_len,
                              size_t payload_len);

keymaster_error_t KM1_ae_update_aad(const TEE_OperationHandle handle,
					                const void *aad, size_t aad_len);

keymaster_error_t KM1_ae_update(const TEE_OperationHandle handle,
                                const void *src, size_t src_len,
                                void *dst, size_t *dst_len,
                                const uint32_t need_buffering);

keymaster_error_t KM1_ae_encrypt_final(const TEE_OperationHandle handle,
                                       const void *src, size_t src_len,
                                       void *dst, size_t *dst_len,
                                       void *tag, size_t *tag_len);
keymaster_error_t KM1_ae_decrypt_final(const TEE_OperationHandle handle,
                                       const void *src, size_t src_len,
                                       void *dst, size_t *dst_len,
                                       const void *tag, size_t tag_len);

keymaster_error_t KM1_free_operation(const TEE_OperationHandle handle);

keymaster_error_t KM1_load_key(TEE_ObjectHandle *keyobj,
		const uint8_t *id, uint32_t id_len,
		uint32_t obj_type, uint32_t key_len);

keymaster_error_t KM1_release_key(TEE_ObjectHandle keyobj);
#endif
