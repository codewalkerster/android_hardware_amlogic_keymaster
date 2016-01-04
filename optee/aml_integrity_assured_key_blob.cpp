/*
 * Copyright 2015 The Android Open Source Project
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

#include "aml_integrity_assured_key_blob.h"

#include <assert.h>

#include <new>
#include <tee_client_api.h>
#include <tee_api_types.h>

#include <openssl/hmac.h>
#include <openssl/mem.h>

#include <keymaster/android_keymaster_utils.h>
#include <keymaster/authorization_set.h>

#include "openssl_err.h"
//#include "keymaster1_secure_api.h"
//
extern keymaster_error_t KM1_hmac_keyblob_init(
        keymaster_algorithm_t android_algo,
        keymaster_digest_t digest,
        TEE_OperationHandle* operation);
extern keymaster_error_t KM1_hmac_update(
        TEE_OperationHandle digest_op,
        const void* chunk,
        size_t chunk_len);

extern keymaster_error_t KM1_hmac_final(
        TEE_OperationHandle hmac_op,
        const void* chunk, size_t chunk_len,
        void* hash, size_t* hash_len);

extern keymaster_error_t KM1_hmac_final_compare(
        TEE_OperationHandle hmac_op,
        const void* chunk, size_t chunk_len,
        const void* hash, size_t hash_len);

extern keymaster_error_t KM1_free_operation(const TEE_OperationHandle handle);

namespace keymaster {

static const uint8_t BLOB_VERSION = 0;
static const size_t HMAC_SIZE = 8;
static const char HMAC_KEY[] = "IntegrityAssuredBlob0";

inline size_t min(size_t a, size_t b) {
    if (a < b)
        return a;
    return b;
}

class HmacCleanup {
  public:
    HmacCleanup(TEE_OperationHandle *op) : op_(op) {}
    ~HmacCleanup() {
        keymaster_error_t error = KM_ERROR_OK;
        error = KM1_free_operation(*op_);
        if (error != KM_ERROR_OK)
            LOG_D("[HmacCleanup]: KM1_free_operation(%p) failed\n", op_);
    }

  private:
    TEE_OperationHandle* op_;
};

static keymaster_error_t ComputeHmac(const uint8_t* serialized_data, size_t serialized_data_size,
                              const AuthorizationSet& hidden, uint8_t hmac[HMAC_SIZE], bool verify) {
    size_t hidden_bytes_size = hidden.SerializedSize();
    UniquePtr<uint8_t[]> hidden_bytes(new  (std::nothrow) uint8_t[hidden_bytes_size]);
    if (!hidden_bytes.get())
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    hidden.Serialize(hidden_bytes.get(), hidden_bytes.get() + hidden_bytes_size);

	TEE_OperationHandle op = 0;
    keymaster_error_t error = KM_ERROR_OK;
    error = KM1_hmac_keyblob_init(KM_ALGORITHM_HMAC, KM_DIGEST_SHA_2_256, &op);
    if (error != KM_ERROR_OK) {
        return KM_ERROR_INVALID_KEY_BLOB;
    }
    HmacCleanup cleanup(&op);

    uint8_t tmp[EVP_MAX_MD_SIZE];
    unsigned tmp_len = EVP_MAX_MD_SIZE;
    if (!verify) {
        if (KM1_hmac_update(op, serialized_data, serialized_data_size) ||
                KM1_hmac_update(op, hidden_bytes.get(), hidden_bytes_size) ||  //
                KM1_hmac_final(op, NULL, 0, tmp, &tmp_len)) {
			error = KM_ERROR_INVALID_KEY_BLOB;
			goto exit;
		}

        assert(tmp_len >= HMAC_SIZE);
        memcpy(hmac, tmp, min(HMAC_SIZE, tmp_len));
    } else {
        if (KM1_hmac_update(op, serialized_data, serialized_data_size) ||
                KM1_hmac_update(op, hidden_bytes.get(), hidden_bytes_size) ||  //
                KM1_hmac_final_compare(op, NULL, 0, hmac, HMAC_SIZE)) {
            error = KM_ERROR_INVALID_KEY_BLOB;
			goto exit;
		}
    }

exit:
    return error;
}

keymaster_error_t AmlSerializeIntegrityAssuredBlob(const KeymasterKeyBlob& key_material,
                                                const AuthorizationSet& hidden,
                                                const AuthorizationSet& hw_enforced,
                                                const AuthorizationSet& sw_enforced,
                                                KeymasterKeyBlob* key_blob) {
    size_t size = 1 /* version */ +                //
                  key_material.SerializedSize() +  //
                  hw_enforced.SerializedSize() +   //
                  sw_enforced.SerializedSize() +   //
                  HMAC_SIZE;

    if (!key_blob->Reset(size))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    uint8_t* p = key_blob->writable_data();
    *p++ = BLOB_VERSION;
    p = key_material.Serialize(p, key_blob->end());
    p = hw_enforced.Serialize(p, key_blob->end());
    p = sw_enforced.Serialize(p, key_blob->end());

    return ComputeHmac(key_blob->key_material, p - key_blob->key_material, hidden, p, false);
}

keymaster_error_t AmlDeserializeIntegrityAssuredBlob(const KeymasterKeyBlob& key_blob,
                                                  const AuthorizationSet& hidden,
                                                  KeymasterKeyBlob* key_material,
                                                  AuthorizationSet* hw_enforced,
                                                  AuthorizationSet* sw_enforced) {
    const uint8_t* p = key_blob.begin();
    const uint8_t* end = key_blob.end();

    if (p > end || p +  HMAC_SIZE > end)
        return KM_ERROR_INVALID_KEY_BLOB;

    uint8_t computed_hmac[HMAC_SIZE];
    memcpy(computed_hmac, key_blob.end() - HMAC_SIZE, HMAC_SIZE);
    keymaster_error_t error = ComputeHmac(key_blob.begin(), key_blob.key_material_size - HMAC_SIZE,
                                          hidden, computed_hmac, true);
    if (error != KM_ERROR_OK)
        return error;

    if (*p != BLOB_VERSION)
        return KM_ERROR_INVALID_KEY_BLOB;
    ++p;

    if (!key_material->Deserialize(&p, end) ||  //
        !hw_enforced->Deserialize(&p, end) ||   //
        !sw_enforced->Deserialize(&p, end))
        return KM_ERROR_INVALID_KEY_BLOB;

    return KM_ERROR_OK;
}

}  // namespace keymaster;
