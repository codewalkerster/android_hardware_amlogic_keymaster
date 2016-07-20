#ifndef __KEYMASTER_CA_H__
#define __KEYMASTER_CA_H__

#include <hardware/keymaster_common.h>
#include <tee_api_types.h>
#include <utee_defines.h>
#include <tee_client_api.h>
#include "otz_id_keymaster.h"

struct aml_keyblob {
	uint8_t handle[64];
	uint32_t optee_obj_type;
	uint32_t key_len;
	uint32_t algo;
};
typedef struct aml_keyblob aml_keyblob_t;

TEEC_Result Initialize_ca(void);

TEEC_Result Terminate_ca(void);

bool get_ca_inited();

TEEC_Result get_keypair_public_ca(const TEE_ObjectHandle handle,
				 uint8_t** x509_data, size_t* x509_data_len);

TEEC_Result delete_key_ca(const uint8_t *id, uint32_t id_len);

TEEC_Result query_key_existence_ca(const TEE_ObjectHandle handle);

TEEC_Result asymmetric_en_de_crypt_tee_ca(
		TEE_OperationHandle oph,
		TEE_OperationMode op_mode,
		const TEE_Attribute *params,
		uint32_t paramCount,
		const void *src,
		size_t src_len,
		void *dst,
		size_t *dst_len);

TEEC_Result generate_dsa_keypair_ca(uint8_t *id, uint32_t id_len,
        const keymaster_dsa_keygen_params_t* dsa_params);

TEEC_Result generate_ec_keypair(uint8_t *id, uint32_t id_len,
        const keymaster_ec_keygen_params_t* ec_params);

TEEC_Result generate_rsa_keypair_ca(uint8_t *id, uint32_t id_len,
        const keymaster_rsa_keygen_params_t* rsa_params);

TEEC_Result generate_symmetric_key(uint8_t *id, uint32_t id_len,
        const uint32_t key_len,
        const uint32_t tee_obj_type);

TEEC_Result do_import_keypair_tee_ca(
        const uint8_t* key, const size_t key_file_len,
        const uint32_t key_type, const uint32_t real_key_bits,
        uint8_t *id, uint32_t id_len);

TEEC_Result do_import_symmetric_key_tee_ca(
        const uint8_t* key,
        const size_t key_len,
        const uint32_t key_type,
        uint8_t *id, uint32_t id_len);

TEEC_Result digest_update_ca(TEE_OperationHandle oph,
		const void *chunk,
		size_t chunk_size);

TEEC_Result digest_do_final_ca(TEE_OperationHandle oph,
		const void *chunk,
		size_t chunk_len, void *hash,
		size_t *hash_len);

TEEC_Result map_algo(const uint32_t key_type, const uint32_t key_len, const void* params,
		uint32_t* algo, uint32_t* dlen);

TEEC_Result allocate_operation(TEE_OperationHandle *oph,
		uint32_t algo, uint32_t mode,
		uint32_t max_key_size);

TEE_Result set_operation_key(TEE_OperationHandle oph, TEE_ObjectHandle key);

TEEC_Result free_operation(TEE_OperationHandle oph);

void add_attr(size_t *attr_count, TEE_Attribute *attrs, uint32_t attr_id,
		const void *buf, size_t len);

void add_attr_value(size_t *attr_count, TEE_Attribute *attrs,
		uint32_t attr_id, uint32_t value_a, uint32_t value_b);

TEE_Result pack_attrs(const TEE_Attribute *attrs, uint32_t attr_count,
		uint8_t **buf, size_t *blen);

TEEC_Result asymmetric_verify_tee_ca(TEE_OperationHandle oph,
				     TEE_OperationMode op_mode,
				     const TEE_Attribute *params,
				     uint32_t paramCount,
				     const void *digest,
				     size_t digest_len,
				     const void *signature,
				     size_t signature_len);
TEEC_Result asymmetric_sign_tee_ca(
		TEE_OperationHandle oph,
		TEE_OperationMode op_mode,
		const TEE_Attribute *params,
		uint32_t paramCount,
		const void *src,
		size_t src_len,
		void *dst,
		size_t *dst_len);

TEEC_Result digest_init_ca(const uint32_t main_algo,
        TEE_OperationHandle* oph, uint32_t digest_algo);

TEEC_Result hmac_keyblob_init_ca(const uint32_t hmac_algo,
		const uint32_t hmac_obj_type,
		TEE_OperationHandle* oph);

TEEC_Result cipher_init_ca(TEE_OperationHandle oph,
		const void *iv, size_t iv_len);

TEEC_Result cipher_update_ca(TEE_OperationHandle oph,
		const void *src, size_t src_len,
        void *dst, size_t *dst_len, const uint32_t need_buffing);

TEEC_Result cipher_do_final_ca(TEE_OperationHandle oph,
				   const void *src, size_t src_len,
				   void *dst, size_t *dst_len);

TEEC_Result hmac_init_ca(
		const uint32_t main_algo,
		TEE_OperationHandle* op,
		TEE_ObjectHandle key,
		uint32_t key_len);

TEEC_Result hmac_update_ca(
		TEE_OperationHandle oph,
		const void *chunk,
		size_t chunk_size);

TEEC_Result hmac_do_final_ca(
        TEE_OperationHandle oph,
        const void *chunk,
        size_t chunk_len, void *hash,
        size_t *hash_len);

TEEC_Result hmac_do_final_compare_ca(
        TEE_OperationHandle oph,
        const void *chunk,
        size_t chunk_len, const void *hash,
        size_t hash_len);

TEEC_Result export_key(
		const uint8_t *id, uint32_t id_len,
        uint32_t obj_type, uint32_t key_len,
		uint8_t** x509_data, size_t* x509_data_len);

TEEC_Result tee_ae_init(const TEE_OperationHandle oph,
        const void *nonce, size_t nonce_len,
        size_t tag_len, size_t aad_len,
        size_t payload_len);

TEEC_Result tee_ae_update_aad(const TEE_OperationHandle oph,
        const void *aad, size_t aad_len);

TEEC_Result tee_ae_update(const TEE_OperationHandle oph,
                             const void *src, size_t src_len,
                             void *dst, size_t *dst_len,
                             const uint32_t need_buffering);

TEEC_Result tee_ae_encrypt_final(const TEE_OperationHandle oph,
        const void *src,
        size_t src_len, void *dst,
        size_t *dst_len, void *tag,
        size_t *tag_len);

TEEC_Result tee_ae_decrypt_final(const TEE_OperationHandle oph,
        const void *src, size_t src_len,
        void *dst, size_t *dst_len,
        const void *tag, size_t tag_len);

TEEC_Result load_key_ca(TEE_ObjectHandle *key,
		const uint8_t *id, uint32_t id_len,
		uint32_t obj_type, uint32_t key_len);

TEEC_Result release_key_ca(TEE_ObjectHandle key);
#endif
