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

#include <iostream>
#include <algorithm>
//#include <keystore/keystore.h>

#include <hardware/hardware.h>
#include <hardware/keymaster0.h>
#include <hardware/keymaster1.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include <UniquePtr.h>
#include <cutils/log.h>

#include <keymaster/logger.h>
#include <keymaster/android_keymaster_utils.h>
#include <keymaster/authorization_set.h>
#include <keymaster/keymaster_enforcement.h>
#include "aml_keymaster_context.h"

// For debugging
//#define LOG_NDEBUG 0
#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG "AmlKeyMaster"
#endif

#define CHK_ERR_AND_LEAVE(error, msg, label) \
    if (error != KM_ERROR_OK) {\
        LOG_D("%s, error:%d\n", msg, error); \
        goto label;\
    }
#define MAX_DIGEST_SIZE (64) /* SHA-512 */
#define MinHmacLength (8)
//#include <aml_keymaster1_keyblob_utils.h>
//#ifdef USE_HW_KEYMASTER
#include <keymaster1_secure_api.h>
#include <tee_api_types.h>
#include <tee_api_defines.h>

using namespace keymaster;

static const size_t GCM_NONCE_SIZE = 12;
static const size_t GCM_MAX_TAG_LENGTH = 16;
static const size_t GCM_MIN_TAG_LENGTH = 12;
// Debug
struct tag_table_entry {
    const char *name;
    keymaster_tag_t tag;
};

static struct tag_table_entry tag_table[] =
{
    {"KM_TAG_PURPOSE", KM_TAG_PURPOSE},
    {"KM_TAG_ALGORITHM", KM_TAG_ALGORITHM},
    {"KM_TAG_KEY_SIZE", KM_TAG_KEY_SIZE},
    {"KM_TAG_BLOCK_MODE", KM_TAG_BLOCK_MODE},
    {"KM_TAG_DIGEST", KM_TAG_DIGEST},
    {"KM_TAG_PADDING", KM_TAG_PADDING},
    {"KM_TAG_CALLER_NONCE", KM_TAG_CALLER_NONCE},
    {"KM_TAG_MIN_MAC_LENGTH", KM_TAG_MIN_MAC_LENGTH},
    {"KM_TAG_RSA_PUBLIC_EXPONENT", KM_TAG_RSA_PUBLIC_EXPONENT},
    {"KM_TAG_BLOB_USAGE_REQUIREMENTS", KM_TAG_BLOB_USAGE_REQUIREMENTS},
    {"KM_TAG_BOOTLOADER_ONLY", KM_TAG_BOOTLOADER_ONLY},
    {"KM_TAG_ACTIVE_DATETIME", KM_TAG_ACTIVE_DATETIME},
    {"KM_TAG_ORIGINATION_EXPIRE_DATETIME", KM_TAG_ORIGINATION_EXPIRE_DATETIME},
    {"KM_TAG_USAGE_EXPIRE_DATETIME",KM_TAG_USAGE_EXPIRE_DATETIME},
    {"KM_TAG_MIN_SECONDS_BETWEEN_OPS",KM_TAG_MIN_SECONDS_BETWEEN_OPS},
    {"KM_TAG_MAX_USES_PER_BOOT",KM_TAG_MAX_USES_PER_BOOT},
    {"KM_TAG_ALL_USERS", KM_TAG_ALL_USERS},
    {"KM_TAG_USER_ID", KM_TAG_USER_ID},
    {"KM_TAG_USER_SECURE_ID",KM_TAG_USER_SECURE_ID},
    {"KM_TAG_NO_AUTH_REQUIRED",KM_TAG_NO_AUTH_REQUIRED},
    {"KM_TAG_USER_AUTH_TYPE ", KM_TAG_USER_AUTH_TYPE},
    {"KM_TAG_AUTH_TIMEOUT ",KM_TAG_AUTH_TIMEOUT },
    {"KM_TAG_ALL_APPLICATIONS ", KM_TAG_ALL_APPLICATIONS },
    {"KM_TAG_APPLICATION_ID", KM_TAG_APPLICATION_ID},
    {"KM_TAG_APPLICATION_DATA ",KM_TAG_APPLICATION_DATA },
    {"KM_TAG_CREATION_DATETIME ",KM_TAG_CREATION_DATETIME },
    {"KM_TAG_ORIGIN ", KM_TAG_ORIGIN },
    {"KM_TAG_ROLLBACK_RESISTANT ", KM_TAG_ROLLBACK_RESISTANT },
    {"KM_TAG_ROOT_OF_TRUST",  KM_TAG_ROOT_OF_TRUST},
    {"KM_TAG_ASSOCIATED_DATA ",KM_TAG_ASSOCIATED_DATA},
    {"KM_TAG_NONCE", KM_TAG_NONCE},
    {"KM_TAG_AUTH_TOKEN",KM_TAG_AUTH_TOKEN},
    {"KM_TAG_MAC_LENGTH", KM_TAG_MAC_LENGTH},
};

const size_t tag_table_size = sizeof(tag_table)/sizeof(struct tag_table_entry);

static void dump_tag_item_value(const char *name, const keymaster_key_param_t* item)
{
    keymaster_tag_type_t type = KM_INVALID;

    if (item) {
        type = keymaster_tag_get_type(item->tag);
        switch (type) {
            case KM_ULONG:
            case KM_ULONG_REP:
                LOG_I("%s: %llx", name, item->long_integer);
                break;
            case KM_DATE:
                LOG_I("%s: %llx", name, item->date_time);
                break;
            case KM_BYTES:
            case KM_BIGNUM:
                LOG_I("%s: blob data: %p, len: %x", name, item->blob.data, item->blob.data_length);
                break;
            case KM_ENUM:
            case KM_ENUM_REP:
                LOG_I("%s: %x", name, item->enumerated);
                break;
            case KM_BOOL:
                LOG_I("%s: %x", name, item->boolean);
                break;
            case KM_UINT:
            case KM_UINT_REP:
                LOG_I("%s: %x", name, item->integer);
                break;
            default:
                LOG_I("%s: invalid type: %d", name, item);
                break;
        }
    }
}

static uint32_t digest_size(keymaster_digest_t digest)
{
    uint32_t hash_size_bits = 0;
    switch (digest) {
        case KM_DIGEST_NONE:
            return KM_ERROR_UNSUPPORTED_DIGEST;
        case KM_DIGEST_MD5:
            hash_size_bits = 128;
            break;
        case KM_DIGEST_SHA1:
            hash_size_bits = 160;
            break;
        case KM_DIGEST_SHA_2_224:
            hash_size_bits = 224;
            break;
        case KM_DIGEST_SHA_2_256:
            hash_size_bits = 256;
            break;
        case KM_DIGEST_SHA_2_384:
            hash_size_bits = 384;
            break;
        case KM_DIGEST_SHA_2_512:
            hash_size_bits = 512;
            break;
    };
    return hash_size_bits;
}
// Overhead for PKCS#1 v1.5 signature padding of undigested messages.  Digested messages have
// additional overhead, for the digest algorithmIdentifier required by PKCS#1.
const size_t kPkcs1UndigestedSignaturePaddingOverhead = 11;

struct am_operations {
    TEE_OperationHandle op;
    TEE_ObjectHandle key;
    TEE_OperationMode op_mode;
    TEE_OperationHandle digest;
    keymaster_algorithm_t algorithm;
    keymaster_purpose_t purpose;
    keymaster_padding_t padding;
    keymaster_block_mode_t block_mode;
    uint32_t key_len; /* in bits */
    size_t min_mac_length;
    size_t mac_length;
    /* internal buffer for each cipher */
    Buffer buffer;
    /* AAD buffer for AES GCM mode */
    Buffer aad_buf;
    /* data come in or not for AES GCM mode*/
    bool aes_data_start;
    /* tag length for AES GCM mode */
    uint32_t tag_len;
    /* data size which will be reserve for each AES updation */
    uint32_t aes_data_to_hold;
};
typedef struct am_operations am_operations_t;

typedef UniquePtr<aml_keyblob_t> Unique_aml_keyblob_t;

/* Copy data from aml_key to key_blob */
static int aml_wrap_key(aml_keyblob_t* aml_key, uint8_t** key_blob, size_t* key_blob_len)
{
    Unique_aml_keyblob_t derData(new(aml_keyblob_t));
    int ret = -1;

    /* Sanity Check */
    if (derData.get() == NULL || aml_key == NULL) {
        LOG_D("%s:%d: invalid input\n", __func__, __LINE__);
        goto out;
    }

    /* Copy Data */
    memcpy(derData.get(), aml_key, sizeof(aml_keyblob_t));

    /* Pass Data to Output Buffer */
    *key_blob_len = sizeof(aml_keyblob_t);
    *key_blob = (uint8_t*)derData.release();
    ret = 0;
out:
    return ret;
}

/* Copy data from key_blob to aml_key */
static int aml_unwrap_key(const uint8_t* key_blob, const size_t key_blob_len, aml_keyblob_t* aml_key)
{
    int ret = -1;
    /* Sanity check */
    if (key_blob == NULL || aml_key == NULL || key_blob_len != sizeof(aml_keyblob_t)) {
        LOG_D("%s:%d: invalid input\n", __func__, __LINE__);
        goto out;
    }

    /* Copy Data */
    memcpy(aml_key, key_blob, sizeof(aml_keyblob_t));
    ret = 0;
out:
    return ret;
}

    __attribute__ ((visibility ("default")))
int aml_terminate()
{
    //#ifdef USE_HW_KEYMASTER
#if 0
    return KM_Secure_Terminate();
#else
    return 0;
#endif
}

static const keymaster_algorithm_t supported_algorithms[] = {
    KM_ALGORITHM_RSA, 	KM_ALGORITHM_EC,
    KM_ALGORITHM_AES, 	KM_ALGORITHM_HMAC};

/* keymaster1 APis */
keymaster_error_t aml_get_supported_algorithms(const struct keymaster1_device* dev __unused,
        keymaster_algorithm_t** algorithms,
        size_t* algorithms_length)
{
    const keymaster_algorithm_t* algo_array = supported_algorithms;
    size_t algo_array_size = sizeof(supported_algorithms);
    keymaster_error_t error = KM_ERROR_OK;

    if (!algorithms || !algorithms_length) {
        LOG_D("%s:%d: invalid input\n", __func__, __LINE__);
        error = KM_ERROR_OUTPUT_PARAMETER_NULL;
        goto out;
    }

    *algorithms_length = algo_array_size / sizeof(keymaster_algorithm_t);
    *algorithms = reinterpret_cast<keymaster_algorithm_t*>(malloc(algo_array_size));
    memcpy(*algorithms , algo_array, algo_array_size);
out:
    return error;
}

static const keymaster_block_mode_t supported_block_modes[] = {
    KM_MODE_ECB, KM_MODE_CBC,
    KM_MODE_CTR, KM_MODE_GCM};

keymaster_error_t aml_get_supported_block_modes(const struct keymaster1_device* dev __unused,
        keymaster_algorithm_t algorithm,
        keymaster_purpose_t purpose,
        keymaster_block_mode_t** modes,
        size_t* modes_length)
{
    const keymaster_block_mode_t* block_mode_array = nullptr;
    size_t block_mode_array_size = 0;
    keymaster_error_t error = KM_ERROR_OK;

    if (!modes || !modes_length) {
        LOG_D("%s:%d: invalid input\n", __func__, __LINE__);
        error = KM_ERROR_OUTPUT_PARAMETER_NULL;
        goto out;
    }

    switch (algorithm) {
        case KM_ALGORITHM_AES:
            if (purpose == KM_PURPOSE_ENCRYPT || purpose == KM_PURPOSE_DECRYPT) {
                block_mode_array = supported_block_modes;
                block_mode_array_size = sizeof(supported_block_modes);
            }
            else {
                error = KM_ERROR_UNSUPPORTED_PURPOSE;
            }
            break;
        case KM_ALGORITHM_HMAC:
        case KM_ALGORITHM_EC:
            /* HMAC and EC only support KM_PURPOSE_SIGN and KM_PURPOSE_VERIFY */
            if (purpose == KM_PURPOSE_ENCRYPT || purpose == KM_PURPOSE_DECRYPT) {
                error = KM_ERROR_UNSUPPORTED_PURPOSE;
            }
            break;
        default:
            break;
    }
    if (block_mode_array && block_mode_array_size) {
        *modes_length = block_mode_array_size / sizeof(keymaster_block_mode_t);
        *modes = reinterpret_cast<keymaster_block_mode_t*>(malloc(block_mode_array_size));
        memcpy(*modes , block_mode_array, block_mode_array_size);
    }
    else {
        *modes = nullptr;
        *modes_length = 0;
    }
out:
    return error;
}

static const keymaster_padding_t rsa_supported_sig_padding[] = {
    KM_PAD_NONE, KM_PAD_RSA_PKCS1_1_5_SIGN, KM_PAD_RSA_PSS,
};
static const keymaster_padding_t rsa_supported_crypt_padding[] = {
    KM_PAD_NONE, KM_PAD_RSA_PKCS1_1_5_ENCRYPT, KM_PAD_RSA_OAEP,
};
static const keymaster_padding_t aes_supported_padding_modes[] = {
    KM_PAD_NONE, KM_PAD_PKCS7
};

static keymaster_error_t get_supported_paddings(const keymaster_algorithm_t algorithm,
        const keymaster_purpose_t purpose,
        keymaster_padding_t** modes,
        size_t* modes_length)
{
    const keymaster_padding_t* padding_mode_array = nullptr;
    size_t padding_mode_array_size = 0;
    keymaster_error_t error = KM_ERROR_OK;

    if (!modes || !modes_length) {
        LOG_E("%s:%d: invalid input\n", __func__, __LINE__);
        error = KM_ERROR_OUTPUT_PARAMETER_NULL;
        goto out;
    }

    switch (algorithm) {
        case KM_ALGORITHM_RSA:
            if (purpose == KM_PURPOSE_SIGN || purpose == KM_PURPOSE_VERIFY) {
                padding_mode_array = rsa_supported_sig_padding;
                padding_mode_array_size = sizeof(rsa_supported_sig_padding);
            }
            else if (purpose == KM_PURPOSE_ENCRYPT || purpose == KM_PURPOSE_DECRYPT) {
                padding_mode_array = rsa_supported_crypt_padding;
                padding_mode_array_size = sizeof(rsa_supported_crypt_padding);
            }
            else {
                error = KM_ERROR_UNSUPPORTED_PURPOSE;
            }
            break;
        case KM_ALGORITHM_AES:
            if (purpose == KM_PURPOSE_ENCRYPT || purpose == KM_PURPOSE_DECRYPT) {
                padding_mode_array = aes_supported_padding_modes;
                padding_mode_array_size = sizeof(aes_supported_padding_modes);
                break;
            }
            else {
                error = KM_ERROR_UNSUPPORTED_PURPOSE;
            }
            break;
        case KM_ALGORITHM_HMAC:
        case KM_ALGORITHM_EC:
            /* HMAC and EC only support KM_PURPOSE_SIGN and KM_PURPOSE_VERIFY */
            if (purpose == KM_PURPOSE_ENCRYPT || purpose == KM_PURPOSE_DECRYPT) {
                error = KM_ERROR_UNSUPPORTED_PURPOSE;
            }
            break;
        default:
            error = KM_ERROR_UNSUPPORTED_ALGORITHM;
            break;
    }

    if (padding_mode_array && padding_mode_array_size) {
        *modes_length = padding_mode_array_size / sizeof(keymaster_padding_t);
        *modes = reinterpret_cast<keymaster_padding_t*>(malloc(padding_mode_array_size));
        memcpy(*modes, padding_mode_array, padding_mode_array_size);
    }
    else {
        *modes = nullptr;
        *modes_length = 0;
    }
out:
    return error;
}

keymaster_error_t aml_get_supported_padding_modes(const struct keymaster1_device* dev __unused,
        keymaster_algorithm_t algorithm,
        keymaster_purpose_t purpose,
        keymaster_padding_t** modes,
        size_t* modes_length)
{
    return get_supported_paddings(algorithm, purpose, modes, modes_length);
}

static const keymaster_digest_t ecdsa_supported_digests[] = {
    KM_DIGEST_NONE,	KM_DIGEST_SHA1,		KM_DIGEST_SHA_2_224,	KM_DIGEST_SHA_2_256,
    KM_DIGEST_SHA_2_384,KM_DIGEST_SHA_2_512};

static const keymaster_digest_t hmac_supported_digests[] = {
    KM_DIGEST_SHA1, KM_DIGEST_SHA_2_224, KM_DIGEST_SHA_2_256, KM_DIGEST_SHA_2_384,
    KM_DIGEST_SHA_2_512/*, KM_DIGEST_MD5*/};

static const keymaster_digest_t rsa_supported_digests[] = {
    KM_DIGEST_NONE,      KM_DIGEST_MD5,       KM_DIGEST_SHA1,     KM_DIGEST_SHA_2_224,
    KM_DIGEST_SHA_2_256, KM_DIGEST_SHA_2_384, KM_DIGEST_SHA_2_512};

keymaster_error_t get_supported_digests(
        keymaster_algorithm_t algorithm,
        keymaster_purpose_t purpose,
        keymaster_digest_t** digests,
        size_t* digests_length)
{
    const keymaster_digest_t* digest_array = nullptr;
    size_t digest_array_size = 0;
    keymaster_error_t error = KM_ERROR_OK;

    if (!digests || !digests_length) {
        error = KM_ERROR_OUTPUT_PARAMETER_NULL;
        LOG_D("%s:%d: invalid input\n", __func__, __LINE__);
        goto out;
    }

    switch (algorithm) {
        case KM_ALGORITHM_RSA:
            digest_array = rsa_supported_digests;
            digest_array_size = sizeof(rsa_supported_digests);
            break;
        case KM_ALGORITHM_EC:
            digest_array = ecdsa_supported_digests;
            digest_array_size = sizeof(ecdsa_supported_digests);
            break;
        case KM_ALGORITHM_HMAC:
            digest_array = hmac_supported_digests;
            digest_array_size = sizeof(hmac_supported_digests);
            break;
        case KM_ALGORITHM_AES:
            if (purpose == KM_PURPOSE_SIGN || purpose == KM_PURPOSE_VERIFY) {
                error = KM_ERROR_UNSUPPORTED_PURPOSE;
            }
            break;
        default:
            error = KM_ERROR_UNSUPPORTED_DIGEST;
            LOG_D("%s:%d: invalid input\n", __func__, __LINE__);
            break;
    }

    if (digest_array && digest_array_size) {
        *digests_length = digest_array_size / sizeof(keymaster_digest_t);
        *digests = reinterpret_cast<keymaster_digest_t*>(malloc(digest_array_size));
        memcpy(*digests, digest_array, digest_array_size);
    }
    else {
        *digests_length = 0;
        *digests = nullptr;
    }
out:
    return error;
}

keymaster_error_t aml_get_supported_digests(
        const struct keymaster1_device* dev __unused,
        keymaster_algorithm_t algorithm,
        keymaster_purpose_t purpose,
        keymaster_digest_t** digests,
        size_t* digests_length)
{
    return get_supported_digests(algorithm, purpose, digests, digests_length);
}

static const keymaster_key_format_t symmetric_supported_import_formats[] = {KM_KEY_FORMAT_RAW};
static const keymaster_key_format_t asymmetric_supported_import_formats[] = {KM_KEY_FORMAT_PKCS8};

keymaster_error_t aml_get_supported_import_formats(const struct keymaster1_device* dev __unused,
        keymaster_algorithm_t algorithm,
        keymaster_key_format_t** formats,
        size_t* formats_length)
{
    const keymaster_key_format_t* formats_array = nullptr;
    size_t formats_array_size = 0;
    keymaster_error_t error = KM_ERROR_OK;

    if (!formats || !formats_length) {
        error = KM_ERROR_OUTPUT_PARAMETER_NULL;
        LOG_D("%s:%d: invalid input\n", __func__, __LINE__);
        goto out;
    }

    switch (algorithm) {
        case KM_ALGORITHM_RSA:
        case KM_ALGORITHM_EC:
            formats_array = asymmetric_supported_import_formats;
            formats_array_size = sizeof(asymmetric_supported_import_formats);
            break;
        case KM_ALGORITHM_HMAC:
        case KM_ALGORITHM_AES:
            formats_array = symmetric_supported_import_formats;
            formats_array_size = sizeof(symmetric_supported_import_formats);
            break;
        default:
            error = KM_ERROR_UNSUPPORTED_ALGORITHM;
            LOG_D("%s:%d: invalid input\n", __func__, __LINE__);
            break;
    }
    if (formats_array && formats_array_size) {
        *formats_length = formats_array_size / sizeof(keymaster_key_format_t);
        *formats = reinterpret_cast<keymaster_key_format_t*>(malloc(formats_array_size));
        memcpy(*formats, formats_array, formats_array_size);
    }
    else {
        *formats_length = 0;
        *formats = nullptr;
    }
out:
    return error;
}
static const keymaster_key_format_t asymmetric_supported_export_formats[] = {KM_KEY_FORMAT_X509};

keymaster_error_t aml_get_supported_export_formats(const struct keymaster1_device* dev __unused,
        keymaster_algorithm_t algorithm,
        keymaster_key_format_t** formats,
        size_t* formats_length)
{
    const keymaster_key_format_t* formats_array = nullptr;
    size_t formats_array_size = 0;
    keymaster_error_t error = KM_ERROR_OK;

    if (!formats || !formats_length) {
        error = KM_ERROR_OUTPUT_PARAMETER_NULL;
        LOG_D("%s:%d: invalid input\n", __func__, __LINE__);
        goto out;
    }

    switch (algorithm) {
        case KM_ALGORITHM_RSA:
        case KM_ALGORITHM_EC:
            formats_array = asymmetric_supported_export_formats;
            formats_array_size = sizeof(asymmetric_supported_export_formats);
            break;
        case KM_ALGORITHM_HMAC:
        case KM_ALGORITHM_AES:
            break;
        default:
            error = KM_ERROR_UNSUPPORTED_ALGORITHM;
            LOG_D("%s:%d: invalid input\n", __func__, __LINE__);
            break;
    }

    if (formats_array && formats_array_size) {
        *formats_length = formats_array_size / sizeof(keymaster_key_format_t);
        *formats = reinterpret_cast<keymaster_key_format_t*>(malloc(formats_array_size));
        memcpy(*formats, formats_array, formats_array_size);
    }
    else {
        *formats_length = 0;
        *formats = nullptr;
    }
out:
    return error;
}

keymaster_error_t aml_add_rng_entropy(const struct keymaster1_device* dev __unused, const uint8_t* data __unused,
        size_t data_length __unused)
{
    //LOG_D("%s:%d:\n", __func__, __LINE__);
    return KM_ERROR_OK;
}

static void dump_tags(const char *name, const keymaster_key_param_set_t *params)
{
    size_t i = 0, j =0;
    keymaster_key_param_t* item = params->params;

    LOG_I("==== start dump %s, length (%u)\n", name, params->length);
    for (i = 0; i < params->length; i++) {
        for (j = 0; j < tag_table_size; j++) {
            if (tag_table[j].tag == item[i].tag) {
                dump_tag_item_value(tag_table[j].name, &item[i]);
                break;
            }
        }
    }
    LOG_I("==== end dump %s\n", name);
}

static keymaster_key_characteristics_t* AmlBuildCharacteristics(const AuthorizationSet& hw_enforced,
        const AuthorizationSet& sw_enforced) {
    keymaster_key_characteristics_t* characteristics =
        reinterpret_cast<keymaster_key_characteristics_t*>(
                malloc(sizeof(keymaster_key_characteristics_t)));
    if (characteristics) {
        hw_enforced.CopyToParamSet(&characteristics->hw_enforced);
        sw_enforced.CopyToParamSet(&characteristics->sw_enforced);
    }
    return characteristics;
}

static keymaster_error_t get_and_validate_aes_keygen_params(const AuthorizationSet& params,
        uint32_t* key_len)
{
    keymaster_error_t error = KM_ERROR_OK;
    uint32_t min_mac_length = 0;

    if (!params.GetTagValue(TAG_KEY_SIZE, key_len) ||
            (*key_len != 128 && *key_len != 256 && *key_len != 192)) {
        error = KM_ERROR_UNSUPPORTED_KEY_SIZE;
        goto out;
    }

    if (params.Contains(TAG_BLOCK_MODE, KM_MODE_GCM)) {
        if (!params.GetTagValue(TAG_MIN_MAC_LENGTH, &min_mac_length)) {
            error = KM_ERROR_MISSING_MIN_MAC_LENGTH;
            goto out;
        }
        if ((min_mac_length & 0x7) != 0 ||
                (min_mac_length < kMinGcmTagLength  || min_mac_length > kMaxGcmTagLength)) {
            error = KM_ERROR_UNSUPPORTED_MIN_MAC_LENGTH;
            goto out;
        }
    }
out:
    return error;
}

keymaster_error_t aml_generate_key(const struct keymaster1_device* dev,
        const keymaster_key_param_set_t* params,
        keymaster_key_blob_t* key_blob,
        keymaster_key_characteristics_t** characteristics)
{
    aml_keyblob_t aml_key;
    keymaster_error_t error = KM_ERROR_OK;
    KeymasterKeyBlob generated_blob;
    KeymasterKeyBlob ret_blob;
    AuthorizationSet key_description;
    AuthorizationSet sw_enforced, hw_enforced;
    keymaster_algorithm_t algorithm;

    if (!dev || !params)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;

    if (!key_blob || !characteristics)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    memset(&aml_key, 0, sizeof(aml_keyblob_t));
    if (*characteristics) {
        /*pointer passed in already contains value. Free it first.*/
        keymaster_free_characteristics(*characteristics);
        *characteristics = NULL;
    }

    if (!key_description.Reinitialize(*params)) {
        LOG_D("Reinitialize failed !", 0);
        error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        goto out;
    }

    if (!key_description.GetTagValue(TAG_ALGORITHM, &algorithm)) {
        LOG_D("Cannot get algorithm!", 0);
        error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        goto out;
    }

    if (algorithm == KM_ALGORITHM_AES) {
        error = get_and_validate_aes_keygen_params(key_description, &aml_key.key_len);
        CHK_ERR_AND_LEAVE(error, "get_and_validate_aes_keygen_params failed", out);
    }

    error = KM1_secure_generate_key(key_description, &aml_key, &generated_blob, &hw_enforced, &sw_enforced);
    if (error != KM_ERROR_OK) {
        LOG_E("%s:%d: KM1_secure_generate_key failed\n", __func__, __LINE__);
        goto out;
    }
    *key_blob = generated_blob.release();

    //dump_tags("description",params);
    if (characteristics) {
        *characteristics = AmlBuildCharacteristics(hw_enforced, sw_enforced);
        if (!*characteristics) {
            LOG_D("allocating characteristics failed", 0);
            error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
            goto out;
        }
    }

out:
    if (error != KM_ERROR_OK) {
        KM1_delete_key(aml_key.handle, sizeof(aml_key.handle));
    }

    return error;
}

keymaster_error_t aml_get_key_characteristics(
        const struct keymaster1_device* dev __unused,
        const keymaster_key_blob_t* key_blob,
        const keymaster_blob_t* client_id,
        const keymaster_blob_t* app_data,
        keymaster_key_characteristics_t** characteristics)
{
	keymaster_error_t error = KM_ERROR_OK;
	KeymasterKeyBlob blob(*key_blob);
	AuthorizationSet additional_params;
	KeymasterKeyBlob key_material;
	AuthorizationSet hw_enforced, sw_enforced;

	additional_params.Clear();
	if (client_id)
        additional_params.push_back(TAG_APPLICATION_ID, *client_id);
    if (app_data)
        additional_params.push_back(TAG_APPLICATION_DATA, *app_data);

    error = AmlParseKeyBlob(blob, additional_params,
            &key_material, &hw_enforced, &sw_enforced);
    if (error != KM_ERROR_OK) {
        LOG_E("fail to parse keyblob", 0);
        return error;
    }

    *characteristics = AmlBuildCharacteristics(hw_enforced, sw_enforced);
out:
	return error;
}

keymaster_error_t aml_import_key(const struct keymaster1_device* dev __unused,
        const keymaster_key_param_set_t* params,
        keymaster_key_format_t key_format,
        const keymaster_blob_t* key_data,
        keymaster_key_blob_t* key_blob,
        keymaster_key_characteristics_t** characteristics)
{
    keymaster_error_t error = KM_ERROR_OK;
    keymaster_algorithm_t algorithm;
    //uint64_t public_exponent;
    uint32_t optee_obj_type = 0;
    KeymasterKeyBlob *blob = nullptr;
    KeymasterKeyBlob ret_blob;
    AuthorizationSet sw_enforced, hw_enforced;
    aml_keyblob_t aml_key;

    if (!params || !key_data) {
        LOG_E("invalid input", 0);
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }

    if (!key_blob || !characteristics) {
        LOG_E("invalid output", 0);
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    }
	memset(&aml_key, 0, sizeof(aml_keyblob_t));

    AuthorizationSet key_description(*params);
    KeymasterKeyBlob input_key_material(key_data->data, key_data->data_length);
    AuthorizationSet authorizations;
    if (!key_description.GetTagValue(TAG_ALGORITHM, &algorithm)) {
        LOG_E("invalid input", 0);
        error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        goto out;
    }
    error = update_import_key_description(key_description, algorithm, key_format,
            input_key_material, &authorizations, &optee_obj_type);
    CHK_ERR_AND_LEAVE(error, "UpdateImportKeyDescriptionoutput failed", out);

    aml_key.algo = algorithm;
    if (algorithm == KM_ALGORITHM_RSA || algorithm == KM_ALGORITHM_EC) {
        if (KM_secure_import_keypair(NULL, input_key_material.key_material,
                    input_key_material.key_material_size,
                    &aml_key) < 0) {
            LOG_E("KM_secure_import_keypair fails: %d",
                    input_key_material.key_material_size);
            error = KM_ERROR_UNKNOWN_ERROR;
            goto out;
        }
    } else if (algorithm == KM_ALGORITHM_AES || algorithm ==  KM_ALGORITHM_HMAC) {
        error = KM1_import_symmetric_key(
                algorithm,
                authorizations,
                input_key_material.key_material,
                input_key_material.key_material_size,
                &aml_key);
        CHK_ERR_AND_LEAVE(error, "KM1_import_symmetric_key failed", out);
    } else {
        error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        goto out;
    }

    blob = new KeymasterKeyBlob(reinterpret_cast<uint8_t*>(&aml_key), sizeof(aml_keyblob_t));
    if (!blob) {
        error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        goto out;
    }

    error = AmlCreateKeyBlob(authorizations, KM_ORIGIN_IMPORTED, *blob,
            &ret_blob, &hw_enforced, &sw_enforced);
    if (error != KM_ERROR_OK) {
        LOG_E("AmlCreateKeyBlob failed !", 0);
        goto out;
    }
#if 0
    keymaster_key_param_set_t tmp1, tmp2;
    hw_enforced.CopyToParamSet(&tmp1);
    sw_enforced.CopyToParamSet(&tmp2);
    dump_tags("import hw enfored",&tmp1);
    dump_tags("import sw enfored",&tmp2);
#endif
    *key_blob = ret_blob.release();
    *characteristics = AmlBuildCharacteristics(hw_enforced, sw_enforced);
out:
    if (error!= KM_ERROR_OK) {
        KM1_delete_key(aml_key.handle, sizeof(aml_key.handle));
    }
    if (blob) {
        blob->Clear();
        delete blob;
    }

    return error;
}

keymaster_error_t aml_export_key(const struct keymaster1_device* dev __unused,
        keymaster_key_format_t export_format,
        const keymaster_key_blob_t* key_to_export,
        const keymaster_blob_t* client_id,
        const keymaster_blob_t* app_data,
        keymaster_blob_t* export_data)
{
    keymaster_error_t error = KM_ERROR_OK;
    keymaster_algorithm_t algorithm;
    const aml_keyblob_t* aml_key = nullptr;
    uint8_t* buf = nullptr;
    uint32_t buf_len = 0;

    if (!export_data) {
        LOG_E("invalid output", 0);
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    }

    /* Init output */
    memset(export_data, 0x0, sizeof(keymaster_blob_t));

    KeymasterKeyBlob blob(*key_to_export);
    AuthorizationSet additional_params;
    KeymasterKeyBlob key_material;
    AuthorizationSet hw_enforced, sw_enforced;

    additional_params.Clear();
    if (client_id)
        additional_params.push_back(TAG_APPLICATION_ID, *client_id);
    if (app_data)
        additional_params.push_back(TAG_APPLICATION_DATA, *app_data);
    error = AmlParseKeyBlob(blob, additional_params,
            &key_material,
            &hw_enforced, &sw_enforced);
    CHK_ERR_AND_LEAVE(error, "AmlParseKeyBlob failed", out);
#if 0
    keymaster_key_param_set_t tmp1, tmp2;
    hw_enforced.CopyToParamSet(&tmp1);
    sw_enforced.CopyToParamSet(&tmp2);
    dump_tags("export hw_enforced", &tmp1);
    dump_tags("export sw_enforced", &tmp2);
#endif
    aml_key = reinterpret_cast<const aml_keyblob_t *>(key_material.begin());
    if (export_format != KM_KEY_FORMAT_X509) {
        LOG_E("unsupported export format", 0);
        error = KM_ERROR_UNSUPPORTED_KEY_FORMAT;
        goto out;
    }
    if (!hw_enforced.GetTagValue(TAG_ALGORITHM, &algorithm) &&
            !sw_enforced.GetTagValue(TAG_ALGORITHM, &algorithm)) {
        LOG_E("Cannot get algorithm from tag", 0);
        error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        goto out;
    }
    if (algorithm != KM_ALGORITHM_RSA &&
            algorithm != KM_ALGORITHM_EC) {
        error = KM_ERROR_UNSUPPORTED_KEY_FORMAT;
        goto out;
    }
    error = KM1_export_key(aml_key->handle, sizeof(aml_key->handle),
			aml_key->optee_obj_type, aml_key->key_len,
            &buf, &buf_len);
    CHK_ERR_AND_LEAVE(error, "KM1_export_key failed", out);
    export_data->data = buf;
    export_data->data_length = buf_len;

out:
    if (error != KM_ERROR_OK && buf)
        free(buf);
    return error;
}

keymaster_error_t aml_delete_key(const struct keymaster1_device* dev __unused,
        const keymaster_key_blob_t* key)
{
    keymaster_error_t error = KM_ERROR_OK;
    const aml_keyblob_t* aml_key = nullptr;
    if (!key) {
        LOG_E("%s: %d, invalid input", __func__, __LINE__);
        return  KM_ERROR_INVALID_ARGUMENT;
    }

    KeymasterKeyBlob blob(*key);
    AuthorizationSet additional_params;
    KeymasterKeyBlob key_material;
    AuthorizationSet hw_enforced, sw_enforced;
    error = AmlParseKeyBlob(blob, additional_params,
            &key_material,
            &hw_enforced, &sw_enforced);
    CHK_ERR_AND_LEAVE(error, "AmlParseKeyBlob failed", out);

    aml_key = reinterpret_cast<const aml_keyblob_t*>(key_material.begin());

    error = KM1_delete_key(aml_key->handle, sizeof(aml_key->handle));
    CHK_ERR_AND_LEAVE(error, "KM1_delete_key failed", out);

//    if (key->key_material && key->key_material_size) {
//        delete [] key->key_material;
//    }
out:
    return error;
}

keymaster_error_t aml_delete_all_keys(const struct keymaster1_device* dev __unused)
{
    LOG_D("%s:%d:\n", __func__, __LINE__);
    return KM_ERROR_OK;
}

inline bool is_public_key_algorithm(keymaster_algorithm_t algorithm) {
    switch (algorithm) {
    case KM_ALGORITHM_HMAC:
    case KM_ALGORITHM_AES:
        return false;
    case KM_ALGORITHM_RSA:
    case KM_ALGORITHM_EC:
        return true;
    }

    // Unreachable.
    assert(false);
    return false;
}

static bool is_public_key_operation(const keymaster_algorithm_t algorithm,
                                    const keymaster_purpose_t purpose) {
    if (!is_public_key_algorithm(algorithm))
        return false;

    switch (purpose) {
        case KM_PURPOSE_VERIFY:
        case KM_PURPOSE_ENCRYPT:
            return true;
        case KM_PURPOSE_SIGN:
        case KM_PURPOSE_DECRYPT:
            return false;
    };

    // Unreachable.
    assert(false);
    return false;
}

static keymaster_error_t authorized_purpose(
        const AuthorizationSet& sw_enforced,
        const AuthorizationSet& hw_enforced,
        const keymaster_algorithm_t algorithm,
        const keymaster_purpose_t purpose)
{
    switch (algorithm) {
        case KM_ALGORITHM_EC:
        case KM_ALGORITHM_HMAC:
            if (purpose != KM_PURPOSE_SIGN && purpose != KM_PURPOSE_VERIFY)
                return KM_ERROR_UNSUPPORTED_PURPOSE;
            break;
        case KM_ALGORITHM_AES:
            if (purpose != KM_PURPOSE_ENCRYPT && purpose != KM_PURPOSE_DECRYPT)
                return KM_ERROR_UNSUPPORTED_PURPOSE;
            break;
        default:
            break;
    }

    switch (purpose) {
        case KM_PURPOSE_VERIFY:
        case KM_PURPOSE_ENCRYPT:
        case KM_PURPOSE_SIGN:
        case KM_PURPOSE_DECRYPT:
            if (!is_public_key_operation(algorithm, purpose)) {
                if (sw_enforced.Contains(TAG_PURPOSE, purpose) ||
                    hw_enforced.Contains(TAG_PURPOSE, purpose))
                    return KM_ERROR_OK;
                else
                    return KM_ERROR_INCOMPATIBLE_PURPOSE;
            }
            break;
        default:
            return KM_ERROR_UNSUPPORTED_PURPOSE;
    }

    return KM_ERROR_OK;
}

static keymaster_error_t aml_sym_authorized_purpose(
        const AuthorizationSet& sw_enforced,
        const AuthorizationSet& hw_enforced,
        const keymaster_purpose_t purpose)
{
    switch (purpose) {
        case KM_PURPOSE_ENCRYPT:
        case KM_PURPOSE_DECRYPT:
            if (sw_enforced.Contains(TAG_PURPOSE, purpose) ||
                    hw_enforced.Contains(TAG_PURPOSE, purpose))
                return KM_ERROR_OK;
            return KM_ERROR_UNSUPPORTED_PURPOSE;
            //return KM_ERROR_INCOMPATIBLE_PURPOSE;
        case KM_PURPOSE_VERIFY:
        case KM_PURPOSE_SIGN:
            if (sw_enforced.Contains(TAG_PURPOSE, purpose) ||
                    hw_enforced.Contains(TAG_PURPOSE, purpose))
                return KM_ERROR_OK;
            return KM_ERROR_UNSUPPORTED_PURPOSE;
        default:
            return KM_ERROR_UNSUPPORTED_PURPOSE;
    }
}

static keymaster_error_t check_rsa_digest(const keymaster_digest_t digest,
										  const keymaster_padding_t padding,
                                          const keymaster_purpose_t purpose)
{
	bool require_digest;

    switch (purpose) {
    case KM_PURPOSE_SIGN:
    case KM_PURPOSE_VERIFY:
        require_digest = (padding == KM_PAD_RSA_PSS);
        break;
    case KM_PURPOSE_ENCRYPT:
    case KM_PURPOSE_DECRYPT:
        require_digest = (padding == KM_PAD_RSA_OAEP);
        break;
    default:
        LOG_D("unsupported purpose\n", 0);
        return KM_ERROR_UNSUPPORTED_PURPOSE;
    }
	LOG_D("check_rsa_digest: padding = %u\n", (uint32_t)padding);
	if (digest == KM_DIGEST_NONE) {
        if (require_digest)
            return KM_ERROR_INCOMPATIBLE_DIGEST;
        return KM_ERROR_OK;
    }
    switch (digest) {
        case KM_DIGEST_NONE:
        case KM_DIGEST_MD5:
        case KM_DIGEST_SHA1:
        case KM_DIGEST_SHA_2_224:
        case KM_DIGEST_SHA_2_256:
        case KM_DIGEST_SHA_2_384:
        case KM_DIGEST_SHA_2_512:
            return KM_ERROR_OK;
        default:
            return KM_ERROR_UNSUPPORTED_DIGEST;
    }
}

static uint32_t get_digest_length(const keymaster_digest_t digest)
{
    uint32_t hash_size_bits = 0;
    switch (digest) {
        case KM_DIGEST_MD5:
            hash_size_bits = 128;
            break;
        case KM_DIGEST_SHA1:
            hash_size_bits = 160;
            break;
        case KM_DIGEST_SHA_2_224:
            hash_size_bits = 224;
            break;
        case KM_DIGEST_SHA_2_256:
            hash_size_bits = 256;
            break;
        case KM_DIGEST_SHA_2_384:
            hash_size_bits = 384;
            break;
        case KM_DIGEST_SHA_2_512:
            hash_size_bits = 512;
            break;
        case KM_DIGEST_NONE:
        default:
            break;
    };
    return hash_size_bits >> 3;
}
static keymaster_error_t get_and_validate_rsa_params(const AuthorizationSet& begin_params,
        const AuthorizationSet& sw_enforced,
        const AuthorizationSet& hw_enforced,
        const keymaster_purpose_t purpose,
        const aml_keyblob_t* aml_key,
        keymaster_padding_t* padding,
        keymaster_digest_t* digest)
{
    keymaster_error_t error = KM_ERROR_OK;
    bool digest_specified = false;
    uint32_t key_len = 0;
    uint32_t digest_len = 0;

    if (begin_params.GetTagCount(TAG_PADDING) != 1) {
        error = KM_ERROR_UNSUPPORTED_PADDING_MODE;
        LOG_E("number of padding must be exactly 1", 0);
        goto out;
    }
    begin_params.GetTagValue(TAG_PADDING, padding);

    if (purpose == KM_PURPOSE_SIGN || purpose == KM_PURPOSE_VERIFY ||
            *padding == KM_PAD_RSA_OAEP) {
        if (begin_params.GetTagCount(TAG_DIGEST) != 1) {
            error = KM_ERROR_UNSUPPORTED_DIGEST;
            LOG_E("number of digeset must be exactly 1", 0);
            goto out;
        }
    }
    /* if we can get digest, use it; otherwise, set to KM_DIGEST_NONE */
    if (!begin_params.GetTagValue(TAG_DIGEST, digest)) {
        *digest = KM_DIGEST_NONE;
    }
    else {
        digest_specified = true;
    }

    switch (*padding) {
        case KM_PAD_RSA_PKCS1_1_5_SIGN:
            if (purpose != KM_PURPOSE_SIGN && purpose != KM_PURPOSE_VERIFY) {
                error = KM_ERROR_UNSUPPORTED_PADDING_MODE;
                LOG_E("KM_PAD_RSA_PKCS1_1_5_SIGN: only supports sign and verify", 0);
                goto out;
            }
            if (!digest_specified) {
                error = KM_ERROR_INCOMPATIBLE_DIGEST;
                LOG_E("KM_PAD_RSA_PKCS1_1_5_SIGN: require a digest", 0);
                goto out;
            }
            break;
        case KM_PAD_RSA_PSS:
            if (purpose != KM_PURPOSE_SIGN && purpose != KM_PURPOSE_VERIFY) {
                error = KM_ERROR_UNSUPPORTED_PADDING_MODE;
                LOG_E("KM_PAD_RSA_PSS: only supports sign and verify", 0);
                goto out;
            }
            if (!digest_specified || *digest == KM_DIGEST_NONE) {
                error = KM_ERROR_INCOMPATIBLE_DIGEST;
                LOG_E("KM_PAD_RSA_PSS: should not specify KM_DIGEST_NONE", 0);
                goto out;
            }

            key_len = aml_key->key_len >> 3; /* in bytes */
            digest_len = get_digest_length(*digest);
            if (key_len - digest_len < 22) {
                error = KM_ERROR_INCOMPATIBLE_DIGEST;
                LOG_E("KM_PAD_RSA_PSS: key lenght should be at least 22 bytes larger than digest length", 0);
                goto out;
            }
            break;
        case KM_PAD_RSA_PKCS1_1_5_ENCRYPT:
            if (purpose != KM_PURPOSE_ENCRYPT && purpose != KM_PURPOSE_DECRYPT) {
                error = KM_ERROR_UNSUPPORTED_PADDING_MODE;
                LOG_E("KM_PAD_RSA_PKCS1_1_5_ENCRYPT: only supports encrypt and decrypt", 0);
                goto out;
            }
            if (digest_specified) {
                /* TODO: Do we need to return error or just showing the warning message is enough? */
                //error = KM_ERROR_INCOMPATIBLE_DIGEST;
                LOG_E("KM_PAD_RSA_PKCS1_1_5_ENCRYPT: no digest is required", 0);
                //goto out;
            }
            break;
        case KM_PAD_RSA_OAEP:
            if (purpose != KM_PURPOSE_ENCRYPT && purpose != KM_PURPOSE_DECRYPT) {
                error = KM_ERROR_UNSUPPORTED_PADDING_MODE;
                LOG_E("KM_PAD_RSA_OAEP: only supports encrypt and decrypt", 0);
                goto out;
            }
            if (!digest_specified || *digest == KM_DIGEST_NONE) {
                error = KM_ERROR_INCOMPATIBLE_DIGEST;
                LOG_E("KM_PAD_RSA_OAEP: digest cannot be specified to KM_DIGEST_NONE", 0);
                goto out;
            }
            break;
        case KM_PAD_NONE:
            if (purpose == KM_PURPOSE_SIGN || purpose == KM_PURPOSE_VERIFY) {
                if (!digest_specified || *digest != KM_DIGEST_NONE) {
                    error = KM_ERROR_INCOMPATIBLE_DIGEST;
                    LOG_E("KM_PAD_NONE: must specify KM_DIGEST_NONE for cases of sign and verify", 0);
                    goto out;
                }
            }
            else if (purpose == KM_PURPOSE_ENCRYPT || purpose == KM_PURPOSE_DECRYPT) {
                if (digest_specified) {
                    /* TODO: Do we need to return error or just showing the warning message is enough? */
                    //error = KM_ERROR_INCOMPATIBLE_DIGEST;
                    LOG_E("KM_PAD_NONE: no digest is required for encrypt and decrypt", 0);
                    //goto out;
                }
            }
            break;
        default:
            error = KM_ERROR_UNSUPPORTED_PADDING_MODE;
            LOG_E("RSA did not support padding mode(%u)", (uint32_t)(*padding));
            goto out;
    }

    if (purpose == KM_PURPOSE_DECRYPT || purpose == KM_PURPOSE_SIGN) {
        if (!sw_enforced.Contains(TAG_PADDING, *padding) &&
                !hw_enforced.Contains(TAG_PADDING, *padding)) {
            error = KM_ERROR_INCOMPATIBLE_PADDING_MODE;
            LOG_E("private key operation: padding must be authorized", 0);
            goto out;
        }
        if (digest_specified &&
                !sw_enforced.Contains(TAG_DIGEST, *digest) &&
                !hw_enforced.Contains(TAG_DIGEST, *digest)) {
            error = KM_ERROR_INCOMPATIBLE_DIGEST;
            LOG_E("private key operation: digest must be authorized", 0);
            goto out;
        }
    }

out:
    return error;
}

static keymaster_error_t get_and_validate_ecdsa_params(const AuthorizationSet& begin_params,
        const AuthorizationSet& sw_enforced,
        const AuthorizationSet& hw_enforced,
        const keymaster_purpose_t purpose,
        keymaster_padding_t* padding,
        keymaster_digest_t* digest)
{
    keymaster_error_t error = KM_ERROR_OK;
    bool digest_specified = false;
#if 0
    /* TODO: check this with "Authorization enforcement: EC keys" in
https://source.android.com/security/keystore/implementer-ref.html#import_key
*/
    if (begin_params.GetTagCount(TAG_PADDING) != 1) {
        error = KM_ERROR_UNSUPPORTED_PADDING_MODE;
        std::cerr << "number of padding must be exactly 1" << std::endl;
        goto out;
    }
    begin_params.GetTagValue(TAG_PADDING, padding);
#endif
    *padding = KM_PAD_NONE;

    /* if we can get digest, use it; otherwise, set to KM_DIGEST_NONE */
    if (!begin_params.GetTagValue(TAG_DIGEST, digest)) {
        *digest = KM_DIGEST_NONE;
    }
    else {
        digest_specified = true;
    }

    switch (*digest) {
        case KM_DIGEST_NONE:
        case KM_DIGEST_SHA1:
        case KM_DIGEST_SHA_2_224:
        case KM_DIGEST_SHA_2_256:
        case KM_DIGEST_SHA_2_384:
        case KM_DIGEST_SHA_2_512:
            break;
        case KM_DIGEST_MD5:
        default:
            error = KM_ERROR_UNSUPPORTED_DIGEST;
            goto out;
    }

    switch (purpose) {
        case KM_PURPOSE_SIGN:
            if (digest_specified &&
                    !sw_enforced.Contains(TAG_DIGEST, *digest) &&
                    !hw_enforced.Contains(TAG_DIGEST, *digest)) {
                error = KM_ERROR_INCOMPATIBLE_DIGEST;
                LOG_E("private key operation: digest must be authorized", 0);
                goto out;
            }
            break;
        case KM_PURPOSE_VERIFY:
            break;
        default:
            error = KM_ERROR_UNSUPPORTED_PURPOSE;
            LOG_E("ECDSA only supports Sign and Verify.", 0);
            goto out;
    }
out:
    return error;
}

keymaster_error_t generate_iv(const keymaster_block_mode_t block_mode,
        UniquePtr<uint8_t[]>& iv, uint32_t* iv_len) {
    *iv_len = (block_mode == KM_MODE_GCM) ? GCM_NONCE_SIZE : AES_BLOCK_SIZE;
    iv.reset(new (std::nothrow) uint8_t[*iv_len]);
    if (!iv.get())
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    if (RAND_bytes(iv.get(), *iv_len) != 1)
        return TranslateLastOpenSslError();
    return KM_ERROR_OK;
}
keymaster_error_t get_iv(const keymaster_block_mode_t block_mode,
        const keymaster_blob_t& iv_blob,
        //                         uint8_t** iv,
        UniquePtr<uint8_t[]>& iv,
        uint32_t* iv_len)
{
    switch (block_mode) {
        case KM_MODE_GCM:
            if (iv_blob.data_length != GCM_NONCE_SIZE) {
                LOG_E("Expected %d-byte nonce for AES-GCM operation, but got %d bytes",
                        GCM_NONCE_SIZE, iv_blob.data_length);
                return KM_ERROR_INVALID_NONCE;
            }
            break;
        case KM_MODE_CTR:
        case KM_MODE_CBC:
            if (iv_blob.data_length != AES_BLOCK_SIZE) {
                LOG_E("Expected %d-byte nonce for AES operation, but got %d bytes",
                        AES_BLOCK_SIZE, iv_blob.data_length);
                return KM_ERROR_INVALID_NONCE;
            }
            break;
        default:
            return KM_ERROR_INCOMPATIBLE_BLOCK_MODE;
    }
    iv.reset(dup_array(iv_blob.data, iv_blob.data_length));
    if (!iv.get())
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    *iv_len = iv_blob.data_length;

    return KM_ERROR_OK;
}

static keymaster_error_t get_and_validate_aes_params(
        const AuthorizationSet& begin_params,
        const AuthorizationSet& sw_enforced,
        const AuthorizationSet& hw_enforced,
        const keymaster_purpose_t purpose,
        keymaster_padding_t* padding,
        keymaster_block_mode_t* block_mode,
        UniquePtr<uint8_t[]>& iv,
        uint32_t* iv_len,
        uint32_t* mac_len_bytes)

{
    keymaster_error_t error = KM_ERROR_OK;
    bool need_iv = false;
    if (begin_params.GetTagCount(TAG_BLOCK_MODE) != 1) {
        LOG_D("number of block mode must be exactly 1\n", 0);
        error = KM_ERROR_UNSUPPORTED_BLOCK_MODE;
        goto out;
    }
    begin_params.GetTagValue(TAG_BLOCK_MODE, block_mode);

    if (begin_params.GetTagCount(TAG_PADDING) != 1) {
        LOG_D("number of padding mode must be exactly 1\n", 0);
        error = KM_ERROR_UNSUPPORTED_PADDING_MODE;
        goto out;
    }
    begin_params.GetTagValue(TAG_PADDING, padding);

    if (!sw_enforced.Contains(TAG_BLOCK_MODE, *block_mode) &&
        !hw_enforced.Contains(TAG_BLOCK_MODE, *block_mode)) {
        LOG_D("block mode should be authorized\n", 0);
        error = KM_ERROR_INCOMPATIBLE_BLOCK_MODE;
        goto out;
    }

    if (!sw_enforced.Contains(TAG_PADDING, *padding) &&
        !hw_enforced.Contains(TAG_PADDING, *padding)) {
        LOG_D("padding mode should be authorized\n", 0);
        error = KM_ERROR_INCOMPATIBLE_PADDING_MODE;
        goto out;
    }

    if (*block_mode == KM_MODE_GCM) {
        uint32_t min_mac_len = 0;
        uint32_t mac_len_bits = 0;
        if (!begin_params.GetTagValue(TAG_MAC_LENGTH, &mac_len_bits)) {
            LOG_D("GCM mode: in_params should contains MAC_LENGTH\n", 0);
            error = KM_ERROR_MISSING_MAC_LENGTH;
            goto out;
        }
        if ((mac_len_bits & 0x7) != 0 ||
            min_mac_len > kMaxGcmTagLength) {
            error = KM_ERROR_UNSUPPORTED_MAC_LENGTH;
            goto out;
        }
        if (!sw_enforced.GetTagValue(TAG_MIN_MAC_LENGTH, &min_mac_len) &&
            !hw_enforced.GetTagValue(TAG_MIN_MAC_LENGTH, &min_mac_len)) {
            LOG_D("GCM mode: authorization should contains MIN_MAC_LENGTH\n", 0);
            error = KM_ERROR_MISSING_MIN_MAC_LENGTH;
            goto out;
        }
        if (mac_len_bits < min_mac_len) {
            LOG_D("GCM mode: mac length(%u) less than min mac length(%u)\n",
                mac_len_bits,  min_mac_len);
            error = KM_ERROR_INVALID_MAC_LENGTH;
            goto out;
        }
        *mac_len_bytes = mac_len_bits >> 3;
    }
    switch (*block_mode) {
    case KM_MODE_GCM:
    case KM_MODE_CTR:
        need_iv = true;
        if (*padding != KM_PAD_NONE) {
            error = KM_ERROR_INCOMPATIBLE_PADDING_MODE;
            goto out;
        }
        break;
    case KM_MODE_CBC:
        need_iv = true;
    case KM_MODE_ECB:
        if (*padding != KM_PAD_NONE && *padding != KM_PAD_PKCS7) {
            error = KM_ERROR_INCOMPATIBLE_PADDING_MODE;
            goto out;
        }
        break;
    default:
        error = KM_ERROR_UNSUPPORTED_BLOCK_MODE;
        goto out;
    }

    if (need_iv) {
        keymaster_blob_t iv_blob;
        if (purpose == KM_PURPOSE_ENCRYPT) {
            //        UniquePtr<uint8_t[]> iv;
            //        uint32_t iv_len = 0;
            bool caller_nonce_authorized = sw_enforced.GetTagValue(TAG_CALLER_NONCE) ||
                hw_enforced.GetTagValue(TAG_CALLER_NONCE);
            if (!begin_params.GetTagValue(TAG_NONCE, &iv_blob)) {
                error = generate_iv(*block_mode, iv, iv_len);
                CHK_ERR_AND_LEAVE(error, "generate iv fail", out);
            }
            else if (caller_nonce_authorized) {
                error = get_iv(*block_mode, iv_blob, iv, iv_len);
                CHK_ERR_AND_LEAVE(error, "get iv fail", out);
            }
            else {
                LOG_D("caller provided nonce/iv but not authorized.\n", 0);
                error = KM_ERROR_CALLER_NONCE_PROHIBITED;
                goto out;
            }
        }
        else if (purpose == KM_PURPOSE_DECRYPT) {
            if (!begin_params.GetTagValue(TAG_NONCE, &iv_blob)) {
                LOG_D("No IV provided\n", 0);
                error = KM_ERROR_INVALID_ARGUMENT;
                goto out;
            }
            error = get_iv(*block_mode, iv_blob, iv, iv_len);
            CHK_ERR_AND_LEAVE(error, "get iv fail", out);
        }
        //output_params.push_back(TAG_NONCE, iv.get(), iv_len);
    }
    else {
        iv.reset(nullptr);
        *iv_len = 0;
    }
out:
    return error;
}

static keymaster_error_t free_and_cleanup_op(am_operations_t* handles)
{
    keymaster_error_t error = KM_ERROR_OK;
    am_operations_t* oph = handles;

    if (handles) {
        if (oph->op) {
            error = KM1_free_operation(oph->op);
            if (error != KM_ERROR_OK)
                LOG_D("[free_and_cleanup_op]: KM1_free_operation(%p) failed\n", oph->op);
        }
        if (oph->key) {
            error = KM1_release_key(oph->key);
            if (error != KM_ERROR_OK)
                LOG_D("[free_and_cleanup_op]: KM1_release_key(%p) failed\n", oph->key);
        }
        if (oph->digest) {
            error = KM1_free_operation(oph->digest);
            if (error != KM_ERROR_OK)
                LOG_D("[free_and_cleanup_op]: KM1_free_operation(%p) failed\n", oph->digest);
        }
        oph->buffer.Clear();
        oph->aad_buf.Clear();
        delete oph;
        oph = nullptr;
    }
    return error;
}

keymaster_error_t aml_begin(
        const struct keymaster1_device *dev __unused,
        keymaster_purpose_t purpose,
        const keymaster_key_blob_t *key,
        const keymaster_key_param_set_t *in_params,
        keymaster_key_param_set_t *out_params,
        keymaster_operation_handle_t *operation_handle)
{
    keymaster_error_t error = KM_ERROR_OK;
    keymaster_padding_t padding;
    keymaster_digest_t digest;
    keymaster_block_mode_t block_mode =(keymaster_block_mode_t)0;
    const aml_keyblob_t* aml_key = nullptr;
    am_operations_t* handles = nullptr;
    keymaster_algorithm_t algorithm;

    if (!key || !in_params) {
        LOG_E("invalid input", 0);
        return KM_ERROR_INVALID_ARGUMENT;
    }

    if (!out_params || !operation_handle) {
        LOG_E("invlid output", 0);
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    }

    /* Init output*/
    *operation_handle = 0;
    memset(out_params, 0, sizeof(keymaster_key_param_set_t));

    KeymasterKeyBlob blob(*key);
    AuthorizationSet additional_params(*in_params);
    KeymasterKeyBlob key_material;
    AuthorizationSet hw_enforced, sw_enforced;
    error = AmlParseKeyBlob(blob, additional_params,
            &key_material,
            &hw_enforced, &sw_enforced);
    if (error != KM_ERROR_OK) {
        LOG_E("AmlParseKeyBlob failed", 0);
        error = KM_ERROR_UNKNOWN_ERROR;
        goto out;
    }
#if 0
    keymaster_key_param_set_t tmp1, tmp2;
    hw_enforced.CopyToParamSet(&tmp1);
    sw_enforced.CopyToParamSet(&tmp2);
    dump_tags("additional_params", in_params);
    dump_tags("hw enfored",&tmp1);
    dump_tags("sw enfored",&tmp2);
#endif
    aml_key = reinterpret_cast<const aml_keyblob_t *>(key_material.begin());

    if (!hw_enforced.GetTagValue(TAG_ALGORITHM, &algorithm) &&
            !sw_enforced.GetTagValue(TAG_ALGORITHM, &algorithm) &&
            !additional_params.GetTagValue(TAG_ALGORITHM, &algorithm)) {
        LOG_E("connot find TAG_ALGORITHM", 0);
        error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        goto out;
    }

    error = authorized_purpose(sw_enforced, hw_enforced, algorithm, purpose);
    if (error != KM_ERROR_OK) {
        LOG_E("authorized_purpose failed: %d, algorithm: %d, purpose: %d", (int32_t)error, (int32_t)algorithm, (int32_t)purpose);
        goto out;
    }

    handles = new am_operations_t;
    if (!handles) {
        LOG_E("malloc failed", 0);
        error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        goto out;
    }

    memset(handles, 0, sizeof(am_operations_t));
    handles->op = nullptr;
    handles->key = nullptr;
    handles->digest = nullptr;
    handles->purpose = purpose;
    handles->algorithm = algorithm;
    handles->key_len = aml_key->key_len;

    error = KM1_load_key(&handles->key, aml_key->handle, sizeof(aml_key->handle),
            aml_key->optee_obj_type, aml_key->key_len);
    if (error != KM_ERROR_OK) {
        LOG_E("KM1_load_key failed", 0);
        goto out;
    }

    if (algorithm == KM_ALGORITHM_RSA) {
        error = get_and_validate_rsa_params(additional_params, sw_enforced, hw_enforced,
                purpose, aml_key, &padding, &digest);
        CHK_ERR_AND_LEAVE(error, "get_and_validate_rsa_params failed", out);

        handles->padding = padding;

        error = KM1_allocate_operation(handles->key, aml_key->key_len,
                algorithm, purpose, digest, padding, block_mode,
                &(handles->op), &(handles->op_mode));
        if (error != KM_ERROR_OK) {
            LOG_E("KM1_allocate_operation failed", 0);
            goto out;
        }

        if (digest != KM_DIGEST_NONE) {
            if (purpose == KM_PURPOSE_SIGN || purpose == KM_PURPOSE_VERIFY) {
                error = KM1_digest_init(algorithm, aml_key->key_len, digest, padding, &(handles->digest));
                if (error != KM_ERROR_OK) {
                    LOG_E("KM1_digest_init failed", 0);
                    goto out;
                }
            }
        }
        *operation_handle = reinterpret_cast<keymaster_operation_handle_t>(handles);
    } else if (algorithm == KM_ALGORITHM_EC) {
        error = get_and_validate_ecdsa_params(additional_params, sw_enforced, hw_enforced,
                purpose, &padding, &digest);
        CHK_ERR_AND_LEAVE(error, "get_and_validate_ecdsa_params failed", out);

        handles->padding = padding;

        error = KM1_allocate_operation(handles->key, aml_key->key_len,
                algorithm, purpose, digest, padding, block_mode,
                &(handles->op), &(handles->op_mode));
        if (error != KM_ERROR_OK) {
            goto out;
        }
        if (digest != KM_DIGEST_NONE) {
            if (purpose == KM_PURPOSE_SIGN || purpose == KM_PURPOSE_VERIFY) {
                error = KM1_digest_init(algorithm, aml_key->key_len, digest, padding, &(handles->digest));
                if (error != KM_ERROR_OK) {
                    goto out;
                }
            }
        }
        *operation_handle = reinterpret_cast<keymaster_operation_handle_t>(handles);
    } else if (algorithm == KM_ALGORITHM_AES) {
        AuthorizationSet authorization_set_out;
        UniquePtr<uint8_t[]> iv;
        uint32_t iv_len = 0;
        uint32_t mac_len_bytes = 0;
        error = get_and_validate_aes_params(additional_params, sw_enforced, hw_enforced,
                purpose, &padding, &block_mode, iv, &iv_len, &mac_len_bytes);
        CHK_ERR_AND_LEAVE(error, "get_and_validate_aes_params failed", out);

        handles->padding = padding;
        handles->block_mode = block_mode;
        handles->aes_data_start = false;
        /* NOTE: the larger size of data to hold will reduce the the times of updation.
           This will improve performace a lot. */
        if (block_mode == KM_MODE_GCM) {
            handles->tag_len = mac_len_bytes;
            handles->aes_data_to_hold = (purpose == KM_PURPOSE_DECRYPT)? mac_len_bytes: 0;
        } else {
            handles->tag_len = 0;
            handles->aes_data_to_hold = 0;
        }
        /* This will also affect the performance. Larger is faster.*/
        handles->buffer.Reinitialize(1024);

        error = KM1_allocate_operation(handles->key, aml_key->key_len,
                algorithm, purpose, KM_DIGEST_NONE,
                padding, block_mode,
                &(handles->op), &(handles->op_mode));
        CHK_ERR_AND_LEAVE(error, "KM1_allocate_operation failed", out);

        if (block_mode == KM_MODE_GCM) {
            handles->aad_buf.Reinitialize(AES_BLOCK_SIZE); /* in bytes */
            error = KM1_ae_init(handles->op, iv.get(), iv_len, mac_len_bytes,
					0 /* aad_len */, 0 /* payload len*/);
        } else {
            error = KM1_cipher_init(handles->op, iv.get(), iv_len);
        }
        CHK_ERR_AND_LEAVE(error, "KM1_ae/cipher_init fails", out);

        if (iv_len && iv.get() && purpose == KM_PURPOSE_ENCRYPT) {
            authorization_set_out.push_back(TAG_NONCE, iv.get(), iv_len);
            authorization_set_out.CopyToParamSet(out_params);
        }
        *operation_handle = reinterpret_cast<keymaster_operation_handle_t>(handles);
    } else if (algorithm == KM_ALGORITHM_HMAC) {
        keymaster_digest_t digest;
        error = aml_sym_authorized_purpose(sw_enforced, hw_enforced, purpose);
        if (error != KM_ERROR_OK) {
            goto out;
        }
        if (!sw_enforced.GetTagValue(TAG_MIN_MAC_LENGTH, &handles->min_mac_length)) {
            LOG_E("HMAC key must have KM_TAG_MIN_MAC_LENGTH", 0);
            error = KM_ERROR_INVALID_KEY_BLOB;
            goto out;
        }
        handles->min_mac_length /= 8;

        if (!hw_enforced.GetTagValue(TAG_DIGEST, &digest)) {
            if (!sw_enforced.GetTagValue(TAG_DIGEST, &digest)) {
                LOG_E("%d digests specified for HMAC key", hw_enforced.GetTagCount(TAG_DIGEST));
                error = KM_ERROR_UNSUPPORTED_DIGEST;
                goto out;
            }
        }

        if (additional_params.GetTagValue(TAG_MAC_LENGTH, &handles->mac_length)) {
            if (purpose == KM_PURPOSE_VERIFY) {
                LOG_E("MAC length may not be specified for verify", 0);
                error = KM_ERROR_INVALID_ARGUMENT;
                goto out;
            }
            handles->mac_length /= 8;
        } else {
            if (purpose == KM_PURPOSE_SIGN) {
                error = KM_ERROR_MISSING_MAC_LENGTH;
                goto out;
            }
            handles->mac_length = digest_size(digest) / 8;
        }

        if (handles->mac_length < handles->min_mac_length) {
            error = KM_ERROR_INVALID_MAC_LENGTH;
            goto out;
        }
        if (handles->mac_length > digest_size(digest) / 8)
        {
            error = KM_ERROR_UNSUPPORTED_MAC_LENGTH;
            goto out;
        }
        error = KM1_hmac_init(handles->key, aml_key->key_len,
                algorithm, digest, &(handles->op));
        if (error != KM_ERROR_OK) {
            goto out;
        }
        *operation_handle = reinterpret_cast<keymaster_operation_handle_t>(handles);
    } else {
            error = KM_ERROR_UNSUPPORTED_ALGORITHM;
            goto out;
    }

    return error;
out:
	free_and_cleanup_op(handles);
    return error;
}

keymaster_error_t store_data(const uint8_t* src, const uint32_t src_len,
        const keymaster_algorithm_t algorithm,
        const uint32_t key_len,
        Buffer& dst, size_t* input_consumed)
{
    keymaster_error_t error = KM_ERROR_OK;

    if (!input_consumed) {
        error = KM_ERROR_OUTPUT_PARAMETER_NULL;
        goto out;
    }
    if (algorithm == KM_ALGORITHM_RSA) {
        if (!dst.reserve(key_len >> 3)) /* in bytes */
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        // If the write fails, it's because input length exceeds key size.
        if (!dst.write(src, src_len)) {
            LOG_E("Input too long: cannot operate on %u bytes of data with %u-byte RSA key",
                    src_len + dst.available_read(), key_len);
            error = KM_ERROR_INVALID_INPUT_LENGTH;
            goto out;
        }
        *input_consumed = src_len;
    }
    else if (algorithm == KM_ALGORITHM_EC) {
        if (!dst.reserve((key_len + 7) / 8)) {
            error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
            goto out;
        }
        /* https://source.android.com/security/keystore/implementer-ref.html
           If the caller provides more data to sign than can be used,
           the data should be silently truncated.*/
        if (!dst.write(src, std::min(dst.available_write(), src_len))) {
            error = KM_ERROR_UNKNOWN_ERROR;
            goto out;
        }

        *input_consumed = src_len;
    }
out:
    return error;
}

keymaster_error_t aes_internal_update_v1(const TEE_OperationHandle op,
                                          const keymaster_purpose_t purpose,
                                          const keymaster_block_mode_t block_mode,
                                          const keymaster_padding_t padding,
                                          const uint8_t* in, const uint32_t in_len,
                                          const uint32_t data_to_hold,
                                          bool direct_push,
                                          Buffer& ibuf,
                                          uint32_t* input_consumed,
                                          uint8_t** out, uint32_t* out_len)
{
    keymaster_error_t error = KM_ERROR_OK;
    uint32_t total = 0;
    uint32_t to_process = 0;
    uint32_t to_read_back = 0;
    uint32_t to_update_block = 0;
    uint32_t need_optee_buffering = 0;
    UniquePtr<uint8_t[]> tmp;
    UniquePtr<uint8_t[]> out_tmp;
    uint32_t out_tmp_len = 0;

    *input_consumed = in_len;

    if (!out || !out_len) {
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    }

    *out = nullptr;
    *out_len = 0;

    if (!in || !in_len) {
        /* no input, nothing to do */
        return KM_ERROR_OK;
    }

    total = ibuf.available_read() + in_len;
    /* total should not be zero, because once in_len = 0, function won't reach here. */
    assert(total > 0);

    if (total <= data_to_hold) {
        if (!ibuf.reserve(in_len)) {
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        }
        ibuf.write(in, in_len);
        goto out;
        //return KM_ERROR_OK;
    }

    if (block_mode == KM_MODE_GCM) {
        to_process = total - data_to_hold;
        //need_optee_buffering = 0;
        //to_update_block = to_process / AES_BLOCK_SIZE;
    } else if (block_mode == KM_MODE_CTR) {
        to_process = total;
        //need_optee_buffering = 1;
    } else {
        /* for ECB and CBC */
        uint32_t remain = total & (AES_BLOCK_SIZE - 1);
        to_update_block = total / AES_BLOCK_SIZE;
        if (!to_update_block) {
            /* total data is less than one block */
            if (!ibuf.reserve(in_len)) {
                return KM_ERROR_MEMORY_ALLOCATION_FAILED;
            }
            ibuf.write(in, in_len);
            goto out;
        } else {
            /* total data is greater than on block */
            if (remain) {
                /* with remain, so output muliple block safely. */
                to_process = total - remain;
                //need_optee_buffering = 0;
            }
            else {
                /* data is just multiple of AES_BLOCK_SIZE */
                if (purpose == KM_PURPOSE_DECRYPT && padding == KM_PAD_PKCS7) {
                    /* reserve on block */
                    to_update_block -= 1;
                }
                to_process = to_update_block * AES_BLOCK_SIZE;
            }
        }
    }
#if 0
    LOG_D("[aes_internal_update_v1] to_process(%u)\n", to_process);
    LOG_D("[aes_internal_update_v1] data_to_hold(%u)\n", data_to_hold);
    LOG_D("[aes_internal_update_v1] need_optee_buffering(%u)\n", need_optee_buffering);
#endif
    /* start to push data into cipher */
    if (to_process) {
        tmp.reset(new uint8_t[to_process]);
        out_tmp.reset(new uint8_t[to_process]);
        out_tmp_len = to_process;
        if (!tmp.get() || !out_tmp.get()) {
            error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
            CHK_ERR_AND_LEAVE(error, "mallocate failed.", out);
        }

        if (to_process >= ibuf.available_read()) {
            /* data to be processed more than which can be read from ibuf */
            uint32_t in_ibuf = ibuf.available_read();
            uint32_t in_input = to_process - in_ibuf;
            ibuf.read(tmp.get(), in_ibuf);
            memcpy(tmp.get() + in_ibuf, in, in_input);
        } else {
            uint32_t in_ibuf = to_process;
            ibuf.read(tmp.get(), in_ibuf);
        }

        if (block_mode == KM_MODE_GCM)
            error = KM1_ae_update(op, tmp.get(), to_process, out_tmp.get(), &out_tmp_len,
                                  need_optee_buffering);
        else
            error = KM1_cipher_update(op, tmp.get(), to_process, out_tmp.get(), &out_tmp_len,
                                      need_optee_buffering);
        CHK_ERR_AND_LEAVE(error, "KM1_ae/cipher_update failed", out);
        assert(to_process == out_tmp_len);

        *out = out_tmp.release();
        *out_len = out_tmp_len;
        //dump_buf("[aes_internal_update_v1] out", *out, *out_len);
    }

    /* start to read back */
    to_read_back = total - to_process;
//    LOG_D("[aes_internal_update_v1] to_read_back(%u)\n", to_read_back);
    if (to_read_back) {
        uint32_t in_ibuf = ibuf.available_read();
        uint32_t in_input = to_read_back - in_ibuf;
        /* read remaining data back into ibuf */
        tmp.reset(new uint8_t[to_read_back]);
        if (!tmp.get()) {
            error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
            CHK_ERR_AND_LEAVE(error, "mallocate failed.", out);
        }
        if (in_ibuf) {
            ibuf.read(tmp.get(), in_ibuf);
            memcpy(tmp.get() + in_ibuf, in, in_input);
        } else {
            uint32_t in_offset = in_len - in_input;
            memcpy(tmp.get(), in + in_offset, in_input);
        }

        if (ibuf.buffer_size() >= to_read_back)
            ibuf.Reinitialize(ibuf.buffer_size());
        else
            ibuf.Reinitialize(ibuf.buffer_size() + to_read_back);

        ibuf.write(tmp.get(), to_read_back);
    }
out:
    if (*out && *out_len) {
        //dump_buf("aes_internal_update_v1 out buf", *out, *out_len);
    }
    return error;
}

keymaster_error_t aml_update(
        const struct keymaster1_device* dev __unused,
        keymaster_operation_handle_t operation_handle,
        const keymaster_key_param_set_t* in_params __unused,
        const keymaster_blob_t* input,
        size_t* input_consumed,
        keymaster_key_param_set_t* out_params,
        keymaster_blob_t* output)
{
    keymaster_error_t error = KM_ERROR_OK;
    AuthorizationSet additional_params;
    am_operations_t* handles = nullptr;

    /* Init output */
    memset(out_params, 0x0, sizeof(keymaster_key_param_set_t));
    memset(output, 0x0, sizeof(keymaster_blob_t));

    if (!operation_handle || !input) {
        LOG_D("invlid input %p %lld", input, operation_handle);
        error = KM_ERROR_INVALID_ARGUMENT;
        goto out;
    }
    if (!input_consumed) {
        LOG_D("invlid %p", input_consumed);
        error = KM_ERROR_OUTPUT_PARAMETER_NULL;
        goto out;
    }

    handles = reinterpret_cast<am_operations_t*>(operation_handle);
#if 0
    LOG_D("handles op(%d)", handles->op);
    LOG_D("handles digest(%d)", handles->digest);
    LOG_D("input->data_length(%u)", input->data_length);
#endif
    if (handles->algorithm == KM_ALGORITHM_RSA ||
        handles->algorithm == KM_ALGORITHM_EC) {
        if (handles->digest) {
            /* With Digest*/
          //  LOG_D("[aml_update]:%d\n", __LINE__);
            error = KM1_digest_update(handles->digest, input->data, input->data_length);
            if (error != KM_ERROR_OK) {
                LOG_D("KM1_digest_update failed\n", 0);
                goto out;
            }
            *input_consumed = input->data_length;
        } else {
            //LOG_D("[aml_update]:%d\n", __LINE__);
            /* Without Digest, Store Data */
            error = store_data(input->data, input->data_length, handles->algorithm,
                               handles->key_len, handles->buffer, input_consumed);
            if (error != KM_ERROR_OK) {
                LOG_D("store_data failed\n", 0);
                goto out;
            }
        }
    } else if (handles->algorithm == KM_ALGORITHM_AES) {
        uint8_t* tmp_buf = nullptr;
        uint32_t tmp_len = 0;
        //uint32_t data_to_hold = 0;
        if (handles->block_mode == KM_MODE_GCM) {
            keymaster_blob_t aad = {.data = nullptr,
                .data_length = 0};
            Buffer& aad_buf = handles->aad_buf;
            //data_to_hold = (handles->purpose == KM_PURPOSE_DECRYPT)? handles->tag_len: 0;
            if (in_params) {
                if (!additional_params.Reinitialize(*in_params)) {
                    error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
                    goto out;
                }
                if (additional_params.GetTagValue(TAG_ASSOCIATED_DATA, &aad)) {
                    if (handles->aes_data_start) {
                        error = KM_ERROR_INVALID_TAG;
                        goto out;
                    }
                    /* accumulate aad data in aad buffer */
                    aad_buf.reserve(aad.data_length);
                    aad_buf.write(aad.data, aad.data_length);
                }
            }
            if (input->data && input->data_length) {
                handles->aes_data_start = true;
                if (aad_buf.available_read()) {
                    /* push out all the data in aad buffer */
                    error = KM1_ae_update_aad(handles->op, aad_buf.peek_read(), aad_buf.available_read());
                    CHK_ERR_AND_LEAVE(error, "KM1_ae_update_aad failed", out);
                    aad_buf.advance_read(aad_buf.available_read());
                }
            }
        }

        error = aes_internal_update_v1(handles->op, handles->purpose,
                                    handles->block_mode, handles->padding,
                                    input->data, input->data_length,
                                    handles->aes_data_to_hold, false,
                                    handles->buffer,
                                    input_consumed, &tmp_buf, &tmp_len);
        CHK_ERR_AND_LEAVE(error, "aes_internal_update_v1 failed", out);
        output->data = tmp_buf;
        output->data_length = tmp_len;
#if 0
        LOG_D("[aml_update]:%d: output->data(%p)\n", __LINE__, output->data);
        LOG_D("[aml_update]:%d: output->data_length(%u)\n", __LINE__, output->data_length);
#endif
    } else if (handles->algorithm == KM_ALGORITHM_HMAC) {
        error = KM1_hmac_update(handles->op, input->data, input->data_length);
        if (error != KM_ERROR_OK) {
            goto out;
        }
        *input_consumed = input->data_length;
    }

out:
    return error;
}

static keymaster_error_t zero_pad_left(UniquePtr<uint8_t[]>* dest, size_t padded_len, Buffer& src)
{
    assert(padded_len > src.available_read());

    dest->reset(new uint8_t[padded_len]);
    if (!dest->get())
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    size_t padding_len = padded_len - src.available_read();
    memset(dest->get(), 0, padding_len);
    if (!src.read(dest->get() + padding_len, src.available_read()))
        return KM_ERROR_UNKNOWN_ERROR;

    return KM_ERROR_OK;
}

static keymaster_error_t asymmetric_sign_undigested(am_operations_t* handles,
        UniquePtr<uint8_t[]>& sig,
        uint32_t* sig_len)
{
    keymaster_error_t error = KM_ERROR_OK;
    const keymaster_algorithm_t algorithm = handles->algorithm;
    if (algorithm == KM_ALGORITHM_RSA) {
        size_t bytes_encrypted = *sig_len;
        size_t key_len_bytes = handles->key_len >> 3; /* in bytes */
        switch (handles->padding) {
            case KM_PAD_NONE:
                {
                    const uint8_t* to_encrypt = handles->buffer.peek_read();
                    UniquePtr<uint8_t[]> zero_padded_in;

                    if (handles->buffer.available_read() > *sig_len) {
                        error = KM_ERROR_INVALID_INPUT_LENGTH;
                        goto out;
                    }
                    else if (handles->buffer.available_read() < *sig_len) {
                        keymaster_error_t error = zero_pad_left(&zero_padded_in, *sig_len, handles->buffer);
                        if (error != KM_ERROR_OK) {
                            goto out;
                        }
                        to_encrypt = zero_padded_in.get();
                    }
                    error = KM1_asymmetric_sign_with_handle(handles->op, handles->op_mode,
                            to_encrypt, *sig_len,
                            sig.get(), &bytes_encrypted);
                    if (error != KM_ERROR_OK) {
                        goto out;
                    }

                    if (bytes_encrypted < *sig_len) {
                        //LOG_D("Do zero padding to out", 0);
                        UniquePtr<uint8_t[]> zero_padded_out;
                        Buffer tmp(sig.get(), bytes_encrypted);
                        error = zero_pad_left(&zero_padded_out, *sig_len, tmp);
                        if (error != KM_ERROR_OK) {
                            goto out;
                        }
                        sig.reset(zero_padded_out.release());
                        bytes_encrypted = *sig_len;
                    }
                    break;
                }
            case KM_PAD_RSA_PKCS1_1_5_SIGN:
                if (handles->buffer.available_read() +
                        kPkcs1UndigestedSignaturePaddingOverhead > key_len_bytes) {
                    LOG_D("Input too long: cannot sign %u-byte message with PKCS1 padding with %u-bit key",
                            handles->buffer.available_read(), handles->key_len);
                    error = KM_ERROR_INVALID_INPUT_LENGTH;
                    goto out;
                }
                *sig_len = handles->buffer.available_read();
                error = KM1_asymmetric_sign_with_handle(handles->op, handles->op_mode,
                        handles->buffer.peek_read(), *sig_len,
                        sig.get(), &bytes_encrypted);
                if (error != KM_ERROR_OK) {
                    goto out;
                }
                break;
            default:
                error = KM_ERROR_UNSUPPORTED_PADDING_MODE;
                goto out;
        }
        *sig_len = bytes_encrypted;
    }
    else if (algorithm == KM_ALGORITHM_EC) {
        error = KM1_asymmetric_sign_with_handle(handles->op, handles->op_mode,
                handles->buffer.peek_read(), handles->buffer.available_read(),
                sig.get(), sig_len);
        CHK_ERR_AND_LEAVE(error, "KM1_asymmetric_sign_with_handle failed", out);
    }
    else {
        error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        goto out;
    }
out:
    return error;
}

static keymaster_error_t asymmetric_verify_undigested(am_operations_t* handles,
        const uint8_t* sig,
        const uint32_t sig_len)
{
    keymaster_error_t error = KM_ERROR_OK;
    if (handles->algorithm == KM_ALGORITHM_RSA) {
        size_t key_len_bytes = handles->key_len >> 3; /* in bytes */
        switch (handles->padding) {
            case KM_PAD_NONE:
                if (handles->buffer.available_read() > key_len_bytes) {
                    error = KM_ERROR_INVALID_INPUT_LENGTH;
                    goto out;
                }
                if (key_len_bytes != sig_len) {
                    error = KM_ERROR_VERIFICATION_FAILED;
                    goto out;
                }
                break;
            case KM_PAD_RSA_PKCS1_1_5_SIGN:
                if (handles->buffer.available_read() +
                        kPkcs1UndigestedSignaturePaddingOverhead > key_len_bytes) {
                    LOG_E("Input too long: cannot verify %u-byte message with PKCS1 padding && %u-bit key",
                            handles->buffer.available_read(), handles->key_len);
                    error = KM_ERROR_INVALID_INPUT_LENGTH;
                    goto out;
                }
                break;
            default:
                error = KM_ERROR_UNSUPPORTED_PADDING_MODE;
                goto out;
        }
    }
    error = KM1_asymmetric_verify_with_handle(handles->op, handles->op_mode,
            handles->buffer.peek_read(), handles->buffer.available_read(),
            sig, sig_len);
    CHK_ERR_AND_LEAVE(error, "KM1_asymmetric_verify_with_handle failed", out);
out:
    return error;
}

static keymaster_error_t asymmetric_sign_digested(const am_operations_t* handles,
        UniquePtr<uint8_t[]>& sig,
        uint32_t* sig_len)

{
    keymaster_error_t error = KM_ERROR_OK;
    uint8_t digest[128] = {0};
    uint32_t digest_len= sizeof(digest);

    error = KM1_digest_final(handles->digest,
            NULL, 0,
            digest, &digest_len);
    if (error != KM_ERROR_OK) {
        goto out;
    }

    error = KM1_asymmetric_sign_with_handle(handles->op, handles->op_mode,
            digest, digest_len,
            sig.get(), sig_len);
    if (error != KM_ERROR_OK) {
        goto out;
    }
out:
    return error;
}

static keymaster_error_t asymmetric_verify_digested(am_operations_t* handles,
        const uint8_t* sig,
        const uint32_t sig_len)
{
    keymaster_error_t error = KM_ERROR_OK;
    /* TEE Digest Final */
    uint8_t digest[128] = {0};
    size_t digest_len = sizeof(digest);
    /* Final Digest */
    error = KM1_digest_final(handles->digest,
            NULL, 0,
            digest, &digest_len);
    CHK_ERR_AND_LEAVE(error, "KM1_digest_final failed", out);

    error = KM1_asymmetric_verify_with_handle(handles->op, handles->op_mode,
            digest, digest_len,
            sig, sig_len);
    CHK_ERR_AND_LEAVE(error, "KM1_asymmetric_verify_with_handle failed", out);
out:
    return error;
}

static keymaster_error_t aes_add_pkcs7(Buffer& internal_buf)
{
    keymaster_error_t error = KM_ERROR_OK;
    uint32_t remain = 0;
    uint32_t bytes_to_pad = 0;

    remain = internal_buf.available_read() & (AES_BLOCK_SIZE - 1);
    bytes_to_pad = AES_BLOCK_SIZE - remain;

    if (!internal_buf.reserve(AES_BLOCK_SIZE)) {
        LOG_D("internal_buf reserve failed\n", 0);
        error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        goto out;
    }
    memset_s(internal_buf.peek_write(), bytes_to_pad, bytes_to_pad);

    if (!internal_buf.advance_write(bytes_to_pad)) {
        LOG_D("internal_buf advance_write failed\n", 0);
        error = KM_ERROR_UNKNOWN_ERROR;
        goto out;
    }
out:
    return error;
}

static keymaster_error_t aes_remove_pkcs7(Buffer& internal_buf)
{
    keymaster_error_t error = KM_ERROR_OK;
    const uint8_t* last_byte_ptr = (internal_buf.end() - 1);
    uint8_t bytes_padded = *(last_byte_ptr);
    uint32_t i = 0;

    //LOG_D("[aes_remove_pkcs7]: bytes_padded(%u)\n", bytes_padded);
    if (bytes_padded < 1 || bytes_padded > AES_BLOCK_SIZE) {
        error = KM_ERROR_INVALID_ARGUMENT;
        CHK_ERR_AND_LEAVE(error, "corrupt padding", out);
    }

    for (i = 1; i < bytes_padded; i++) {
        if (*(last_byte_ptr - i) != bytes_padded) {
            error = KM_ERROR_INVALID_ARGUMENT;
            CHK_ERR_AND_LEAVE(error, "corrupt padding", out);
        }
    }

    if (!internal_buf.advance_write(-(bytes_padded))) {
        LOG_D("internal_buf advance_write failed\n", 0);
        error = KM_ERROR_INVALID_ARGUMENT;
        goto out;
    }
out:
    return error;
}

keymaster_error_t aml_finish(const struct keymaster1_device* dev __unused,
        keymaster_operation_handle_t operation_handle,
        const keymaster_key_param_set_t* in_params __unused,
        const keymaster_blob_t* signature,
        keymaster_key_param_set_t* out_params, keymaster_blob_t* output)
{
    keymaster_error_t error = KM_ERROR_OK;
    am_operations_t *handles = nullptr;
    keymaster_purpose_t purpose;
    keymaster_algorithm_t algorithm;
    uint32_t sig_len = 0;
    UniquePtr<uint8_t[]> sig;
    UniquePtr<uint8_t[]> tmp;

    /* Init output */
    memset(output, 0x0, sizeof(keymaster_blob_t));
    memset(out_params, 0x0, sizeof(keymaster_key_param_set_t));

    if (!operation_handle) {
        error = KM_ERROR_INVALID_ARGUMENT;
        goto out;
    }
    if (!output) {
        error = KM_ERROR_OUTPUT_PARAMETER_NULL;
        goto out;
    }

    handles = reinterpret_cast<am_operations_t *>(operation_handle);
    purpose = handles->purpose;
    algorithm = handles->algorithm;

    if (algorithm == KM_ALGORITHM_RSA) {
        if (purpose == KM_PURPOSE_SIGN) {
            sig_len = handles->key_len >> 3; /* in bytes */

            sig.reset(new uint8_t[sig_len]);
            if (!sig.get()) {
                error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
                goto out;
            }

            if (handles->digest) {
                /* sign digested */
                error = asymmetric_sign_digested(handles, sig, &sig_len);
                CHK_ERR_AND_LEAVE(error, "asymmetric_sign_digested failed", out);
            } else {
                /* sign undigested */
                error = asymmetric_sign_undigested(handles, sig, &sig_len);
                CHK_ERR_AND_LEAVE(error, "asymmetric_sign_undigested failed", out);
            }
            output->data = sig.release();
            output->data_length = sig_len;
        } else if (purpose == KM_PURPOSE_VERIFY) {
            if (handles->digest) {
                /* verify digested */
                error = asymmetric_verify_digested(handles, signature->data, signature->data_length);
                CHK_ERR_AND_LEAVE(error, "asymmetric_verify_digested failed", out);
            } else {
                /* verify undigested */
                error = asymmetric_verify_undigested(handles, signature->data, signature->data_length);
                CHK_ERR_AND_LEAVE(error, "asymmetric_verify_undigested failed", out);
            }
        } else if (purpose == KM_PURPOSE_ENCRYPT || purpose == KM_PURPOSE_DECRYPT) {
            const uint8_t* to_encrypt = handles->buffer.peek_read();
            size_t to_encrypt_len = handles->buffer.available_read();

            sig_len = handles->key_len >> 3; /* in bytes */

            sig.reset(new uint8_t[sig_len]);
            if (!sig.get()) {
                error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
                goto out;
            }

            UniquePtr<uint8_t[]> zero_padded_in;
            if (handles->padding == KM_PAD_NONE && to_encrypt_len < sig_len) {
                error = zero_pad_left(&zero_padded_in, sig_len, handles->buffer);
                if (error != KM_ERROR_OK)
                    return error;
                to_encrypt = zero_padded_in.get();
                to_encrypt_len = sig_len;
            }

            error = KM1_asymmetric_en_de_crypt_with_handle(handles->op, handles->op_mode,
                    to_encrypt, to_encrypt_len,
                    sig.get(), &sig_len);
            CHK_ERR_AND_LEAVE(error, "KM1_asymmetric_en_de_crypt_with_handle failed", out);

            if (handles->padding == KM_PAD_NONE && sig_len < to_encrypt_len) {
                LOG_E("Do zero padding to out", 0);
                UniquePtr<uint8_t[]> zero_padded_out;
                Buffer tmp(sig.get(), sig_len);
                error = zero_pad_left(&zero_padded_out, to_encrypt_len, tmp);
                if (error != KM_ERROR_OK)
                    return error;
                sig.reset(zero_padded_out.release());
                sig_len = to_encrypt_len;
            }

            output->data = sig.release();
            output->data_length = sig_len;
        }
    } else if (algorithm == KM_ALGORITHM_EC) {
        if (purpose == KM_PURPOSE_SIGN) {
            /* signature size = twice the key length plus ASN.1 overhead. 20 bytes for overhead
               should be sufficient and cover the accuracy lost as doing cast. */
            sig_len = (handles->key_len >> 2) /* "x2/8" */ + 20;
            sig.reset(new uint8_t[sig_len]);
            if (!sig.get()) {
                error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
                goto out;
            }
            if (handles->digest) {
                error = asymmetric_sign_digested(handles, sig, &sig_len);
                CHK_ERR_AND_LEAVE(error, "asymmetric_sign_digested failed", out);
            }
            else {
                error = asymmetric_sign_undigested(handles, sig, &sig_len);
                CHK_ERR_AND_LEAVE(error, "asymmetric_sign_undigested failed", out);
            }
            output->data = sig.release();
            output->data_length = sig_len;
        } else if (purpose == KM_PURPOSE_VERIFY) {
            if (handles->digest) {
                error = asymmetric_verify_digested(handles, signature->data, signature->data_length);
                CHK_ERR_AND_LEAVE(error, "asymmetric_verify_digested failed", out);
            }
            else {
                error = asymmetric_verify_undigested(handles, signature->data, signature->data_length);
                CHK_ERR_AND_LEAVE(error, "asymmetric_verify_undigested failed", out);
            }
        } else {
            error = KM_ERROR_UNSUPPORTED_PURPOSE;
            goto out;
        }
    } else if (algorithm == KM_ALGORITHM_AES) {
        Buffer out_buf;
        uint32_t out_len = 0;

        if (handles->block_mode == KM_MODE_GCM) {
            const uint8_t* in = handles->buffer.peek_read();
            uint32_t in_len = handles->buffer.available_read();
            uint32_t tag_len = handles->tag_len;
            UniquePtr<uint8_t[]> out_tmp;
            Buffer& aad_buf = handles->aad_buf;

            if (aad_buf.available_read()) {
                /* Aad should be pushed in aml_update() for most cases.
                   In case of no input in aml_update(), this is the last chance to push
                   aad out. */
                error = KM1_ae_update_aad(handles->op, aad_buf.peek_read(), aad_buf.available_read());
                CHK_ERR_AND_LEAVE(error, "KM1_ae_update_aad failed", out);
                aad_buf.advance_read(aad_buf.available_read());
            }

            if (handles->purpose == KM_PURPOSE_DECRYPT) {
                uint32_t in_but_tag = 0;
                assert(in_len >= tag_len);

                in_but_tag = in_len - tag_len;

                out_len = in_but_tag? in_but_tag : AES_BLOCK_SIZE;
                out_tmp.reset(new uint8_t[out_len]);
                if (!out_tmp.get()) {
                    error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
                    goto out;
                }
                error = KM1_ae_decrypt_final(handles->op, in, in_but_tag, out_tmp.get(), &out_len,
                                             in + in_but_tag, tag_len);
                CHK_ERR_AND_LEAVE(error, "KM1_ae_decrypt_final failed", out);

                assert(out_len == in_but_tag);

                output->data = out_tmp.release();
                output->data_length = out_len;
            } else if (handles->purpose == KM_PURPOSE_ENCRYPT) {
                UniquePtr<uint8_t[]> tag;
                UniquePtr<uint8_t[]> out_local;
                uint32_t out_local_len = 0;

                /* In case in_len is 0, we still need to provide big enough buffer for optee */
                out_local_len = in_len? in_len : AES_BLOCK_SIZE;

                out_local.reset(new uint8_t[out_local_len]);
                tag.reset(new uint8_t[tag_len]);

                if (!out_local.get() || !tag.get()) {
                    error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
                    goto out;
                }

                error = KM1_ae_encrypt_final(handles->op, in, in_len,
                                             out_local.get(), &out_local_len,
                                             tag.get(), &tag_len);
                CHK_ERR_AND_LEAVE(error, "KM1_ae_encrypt_final failed", out);

                assert(tag_len == handles->tag_len);
                assert(out_local_len == in_len);

                out_len = out_local_len + tag_len;
                out_tmp.reset(new uint8_t[out_len]);
                if (!out_tmp.get()) {
                    error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
                    goto out;
                }
                memcpy(out_tmp.get(), out_local.get(), out_local_len);
                memcpy(out_tmp.get() + out_local_len, tag.get(), tag_len);

                output->data = out_tmp.release();
                output->data_length = out_len;
            }
        } else {
            UniquePtr<uint8_t[]> tmp;
            if (purpose == KM_PURPOSE_ENCRYPT &&
                handles->padding == KM_PAD_PKCS7) {
                error = aes_add_pkcs7(handles->buffer);
                CHK_ERR_AND_LEAVE(error, "aes_add_pkcs7 failed", out);
            }

            out_len = handles->buffer.available_read();
            if (handles->block_mode == KM_MODE_ECB || handles->block_mode == KM_MODE_CBC) {
                if (out_len % AES_BLOCK_SIZE) {
                    LOG_D("input size should be multiple of AES_BLOCK_SIZE, padding: %d\n",
							handles->padding);
                    error = KM_ERROR_INVALID_INPUT_LENGTH;
                    goto out;
                }
            }

            if (!out_buf.Reinitialize(out_len)) {
                LOG_D("malloc failed\n", 0);
                goto out;
            }

            error = KM1_cipher_do_final(handles->op,
                    handles->buffer.peek_read(), handles->buffer.available_read(),
                    out_buf.peek_write(), &out_len);
            CHK_ERR_AND_LEAVE(error, "KM1_cipher_do_final failed", out);
            out_buf.advance_write(out_len);

            if (purpose == KM_PURPOSE_DECRYPT &&
                handles->padding == KM_PAD_PKCS7) {
                error = aes_remove_pkcs7(out_buf);
                CHK_ERR_AND_LEAVE(error, "aes_remove_pkcs7 failed", out);
            }
            out_len = out_buf.available_read();
            tmp.reset(new uint8_t[out_len]);
            if (!tmp.get()) {
                error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
                goto out;
            }
            if (!out_buf.read(tmp.get(), out_len)) {
                LOG_D("out_buf read failed\n", 0);
                error = KM_ERROR_UNKNOWN_ERROR;
                goto out;
            }
            output->data = tmp.release();
            output->data_length = out_len;
        }
    } else if (algorithm == KM_ALGORITHM_HMAC) {
        uint32_t digest_len = MAX_DIGEST_SIZE;
        uint8_t digest[MAX_DIGEST_SIZE];
        switch (purpose)
        {
            case KM_PURPOSE_SIGN:
                sig.reset(new uint8_t[MAX_DIGEST_SIZE]);
                if (!sig.get()) {
                    LOG_E("mallocate failed", 0);
                    error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
                    goto out;
                }
                error = KM1_hmac_final(handles->op, NULL, 0,
                        digest, &digest_len);
                if (error != KM_ERROR_OK) {
                    LOG_E("KM1_hmac_update failed", 0);
                    goto out;
                }
                if (handles->mac_length > digest_len) {
                    error = KM_ERROR_UNSUPPORTED_MAC_LENGTH;
                    goto out;
                }
                memcpy(sig.get(), digest, handles->mac_length);
                output->data = sig.release();
                output->data_length = handles->mac_length;
                break;
            case KM_PURPOSE_VERIFY:
                if (signature->data_length > digest_len ||
                        signature->data_length < MinHmacLength) {
                    error = KM_ERROR_UNSUPPORTED_MAC_LENGTH;
                    goto out;
                }
                if (signature->data_length < handles->min_mac_length) {
                    error = KM_ERROR_INVALID_MAC_LENGTH;
                    goto out;
                }

                error = KM1_hmac_final_compare(handles->op, NULL, 0,
                        signature->data, signature->data_length);
                if (error != KM_ERROR_OK) {
                    error = KM_ERROR_VERIFICATION_FAILED;
                    goto out;
                }
                error = KM_ERROR_OK;
                break;
            default:
                error = KM_ERROR_UNSUPPORTED_PURPOSE;
                goto out;
        }
    }
out:
    free_and_cleanup_op(handles);
    return error;
}

keymaster_error_t aml_abort(const struct keymaster1_device* dev __unused,
        keymaster_operation_handle_t operation_handle)
{
    am_operations_t* handles = nullptr;
    keymaster_error_t error = KM_ERROR_OK;

    if (!operation_handle) {
        LOG_E("aml_abort: invlid input\n", 0);
        error = KM_ERROR_UNEXPECTED_NULL_POINTER;
        goto out;
    }

    handles = reinterpret_cast<am_operations_t *>(operation_handle);
    free_and_cleanup_op(handles);

out:
	return error;
}
