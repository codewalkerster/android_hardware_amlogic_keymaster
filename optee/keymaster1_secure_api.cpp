#include <iostream>
#include <keymaster1_secure_api.h>
#include <tee_client_api.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/aes.h>

#include <hardware/keymaster1.h>
#include <hardware/keymaster_defs.h>
#include <tee_api_types.h>
#include <utee_defines.h>
#include <cassert>
#include <cutils/log.h>
#include <keymaster/authorization_set.h>
#include <keymaster/android_keymaster_utils.h>
#include <keymaster/logger.h>
using namespace keymaster;

#define SALT_LEN 		(20)

#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG "AmlKeyMaster"
#endif

static uint32_t android_digest_to_optee(keymaster_digest_t digest)
{
    switch (digest)
    {
        case KM_DIGEST_NONE:
            return 0;
        case KM_DIGEST_MD5:
            return TEE_ALG_MD5;
        case KM_DIGEST_SHA1:
            return TEE_ALG_SHA1;
        case KM_DIGEST_SHA_2_224:
            return TEE_ALG_SHA224;
        case KM_DIGEST_SHA_2_256:
            return TEE_ALG_SHA256;
        case KM_DIGEST_SHA_2_384:
            return TEE_ALG_SHA384;
        case KM_DIGEST_SHA_2_512:
            return TEE_ALG_SHA512;
    }
    return 0;
}

/* The API initializes the crypto hardware.
 *	Parameters:	none
 *	Returns: 	 0  -> success
 *			-1 -> failed
 */
int KM_Secure_Initialize(void)
{
    TEEC_Result result;

    result = Initialize_ca();

    if (result != TEEC_SUCCESS) {
        LOG_D("%s failed", __FUNCTION__);
        return -1;
    }
    return 0;
}


/* The API closes the operation and releases all resources used
 *	Parameters: none
 *	Returns: 0 -> success
 *		-1 -> failed
 */
int KM_Secure_Terminate(void)
{
    TEEC_Result result;
    result = Terminate_ca();
    if (result != TEEC_SUCCESS) {
        LOG_D("%s: failed", __FUNCTION__);
        return -1;
    }
    return 0;
}

/* The API imports a keypair and get the key blob(key handle)
 *	Input:  dev - 		pointer to keymaster1_device_t
 *		key - 		pointer to a keypair
 *		key_len - 	length of the keypair
 *	Output: aml_key - 	pointer to aml_key returned to HAL
 *	Returns: 0 - 		success
 *		-1 - 		failed
 */
int KM_secure_import_keypair(const keymaster1_device_t* dev __unused,
        const uint8_t* key, const size_t key_bin_len,
        aml_keyblob_t* aml_key)
{
    TEE_Result res = TEEC_ERROR_GENERIC;
	//uint32_t key_type = 0;
	//uint32_t key_bits = 0;
    PKCS8_PRIV_KEY_INFO* pkcs8_info = NULL;
    EVP_PKEY *pkey = NULL;
    const uint8_t* temp = key;
    int ret = -1; /* Default */

    /* Sanity Check */
    if (false == get_ca_inited()) {
        if (KM_Secure_Initialize() < 0) {
            LOG_D("%s:%d: KM_Secure_Initialize failed ...\n", __func__, __LINE__);
            goto out;
        }
    }
    /* Get Private Key Info by Openssl */
    pkcs8_info = d2i_PKCS8_PRIV_KEY_INFO(NULL, &temp, key_bin_len);
    if (pkcs8_info == NULL) {
        LOG_D("%s:%d: d2i_PKCS8_PRIV_KEY_INFO returns NULL!\n", __func__, __LINE__);
        goto out;
    }
    /* Convert to Openssl EVP key type */
    pkey = EVP_PKCS82PKEY(pkcs8_info);
    if (pkey == NULL) {
        LOG_D("%s:%d: EVP_PKCS82PKEY returns NULL\n", __func__, __LINE__);
        goto out;
    }
    /* Prepare key info for TEE */
    aml_key->key_len = EVP_PKEY_bits(pkey);
    switch (EVP_PKEY_type(pkey->type)) {
        case EVP_PKEY_DSA:
            aml_key->optee_obj_type = TEE_TYPE_DSA_KEYPAIR;
            break;
        case EVP_PKEY_RSA:
            aml_key->optee_obj_type = TEE_TYPE_RSA_KEYPAIR;
            break;
        case EVP_PKEY_EC:
            aml_key->optee_obj_type = TEE_TYPE_ECDSA_KEYPAIR;
            break;
        default:
            LOG_D("%s:%d: Unsupport key type\n",__func__, __LINE__);
            goto out;
    }
    /* Generate Keypair */
    res = do_import_keypair_tee_ca(key, key_bin_len, aml_key->optee_obj_type,
            aml_key->key_len, aml_key->handle, sizeof(aml_key->handle));
    if (res != TEEC_SUCCESS) {
        LOG_D("do_import_keypair_tee_ca failed: %zd %x\n", key_bin_len, aml_key->optee_obj_type);
        goto out;
    }
    ret = 0;
out:
    if (pkcs8_info)	PKCS8_PRIV_KEY_INFO_free(pkcs8_info);
    if (pkey) EVP_PKEY_free(pkey);

    return ret;
}

/* The API delete a specified keypair
 *	Input: 	handle - secure world key handle.
 *	Output: None
 *	Returns: 0 - 	success
 *		-1 - 	failed
 */
int KM_secure_query_key_existence(const keymaster1_device_t* dev __unused, const TEE_ObjectHandle handle)
{
    TEEC_Result res = TEEC_ERROR_GENERIC;
    res = query_key_existence_ca(handle);
    if (res != TEEC_SUCCESS)
        return -1;
    else
        return 0;
}

static uint32_t supported_rsa_key_len[] = {1024, 2048, 3072, 4096};
static uint64_t supported_rsa_exponent[] = {3, 65537};
static keymaster_error_t check_rsa_keygen_param(const uint32_t len, const uint64_t exponent)
{
    keymaster_error_t error = KM_ERROR_OK;
    /* check key len */
    uint32_t i = 0;
    for (i = 0; i < sizeof(supported_rsa_key_len) / sizeof(uint32_t); i++) {
        if (len == supported_rsa_key_len[i])
            goto out;
    }
    if (!len || (len % 8)) {
        error = KM_ERROR_UNSUPPORTED_KEY_SIZE;
        goto out;
    }
    /* check exponent */
    for (i = 0; i < sizeof(supported_rsa_exponent) / sizeof(uint64_t); i++) {
        if (exponent == supported_rsa_exponent[i])
            goto out;
    }
    /* TODO: check prime up to 2^64 is time-consuming, do we need to check this? */
out:
    return error;
}
static uint32_t supported_ec_key_len[] = {224, 256, 384, 521};
static keymaster_error_t check_ec_keygen_param(const uint32_t len)
{
    /* check key len */
    uint32_t i = 0;
    for (i = 0; i < sizeof(supported_ec_key_len)/sizeof(uint32_t); i++) {
        if (len == supported_ec_key_len[i])
            return KM_ERROR_OK;
    }
    return KM_ERROR_UNSUPPORTED_KEY_SIZE;
}

keymaster_error_t validate_hmac_key_params(
        const AuthorizationSet& key_description) {
    uint32_t min_mac_length_bits;
    if (!key_description.GetTagValue(TAG_MIN_MAC_LENGTH, &min_mac_length_bits))
        return KM_ERROR_MISSING_MIN_MAC_LENGTH;

    keymaster_digest_t digest;
    if (!key_description.GetTagValue(TAG_DIGEST, &digest)) {
        LOG_E("%d digests specified for HMAC key", key_description.GetTagCount(TAG_DIGEST));
        return KM_ERROR_UNSUPPORTED_DIGEST;
    }

    size_t hash_size_bits = 0;
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

    if (hash_size_bits == 0) {
        // digest was not matched
        return KM_ERROR_UNSUPPORTED_DIGEST;
    }

    if (min_mac_length_bits % 8 != 0 || min_mac_length_bits > hash_size_bits)
        return KM_ERROR_UNSUPPORTED_MIN_MAC_LENGTH;

    if (min_mac_length_bits < 64)
        return KM_ERROR_UNSUPPORTED_MIN_MAC_LENGTH;

    return KM_ERROR_OK;
}

bool hmac_key_size_supported(size_t key_size_bits) {
    return key_size_bits > 0 && key_size_bits % 8 == 00 &&
        key_size_bits <= 2048 /* Some RFC test cases require >1024-bit keys */;
}

/* The API generate a keypair and return a key_blob for further access.
 *	Input:  dev - 		pointer to keymaster1_device_t
 *		key_type - 	key type of keypair which will be generated. (EC, DSA, RSA)
 *		key_params - 	metadata of keypair
 *	Output: aml_key - 	aml_keyblob_t returned to HAL
 *	Returns: 0 - 		success
 *		-1 - 		failed
 */
keymaster_error_t KM1_secure_generate_key(
        const AuthorizationSet& key_description,
        aml_keyblob_t *aml_key,
        KeymasterKeyBlob *key_blob,
        AuthorizationSet *hw_enforced,
        AuthorizationSet *sw_enforced)
{
    keymaster_error_t ret = KM_ERROR_OK; /* Default */
    keymaster_algorithm_t algo;
    AuthorizationSet authorizations(key_description);
    KeymasterKeyBlob key_material;

    /* Sanity check */
    if (!aml_key) {
        LOG_D("%s:%d: Invalid input\n", __func__, __LINE__);
        ret = KM_ERROR_INVALID_ARGUMENT;
        goto out;
    }

    if (false == get_ca_inited()) {
        if (KM_Secure_Initialize() < 0) {
            LOG_D("%s:%d: KM_Secure_Initialize failed\n", __func__, __LINE__);
            ret = KM_ERROR_UNKNOWN_ERROR;
            goto out;
        }
    }

    if (!authorizations.GetTagValue(TAG_ALGORITHM, &algo)) {
        LOG_D("%s:%d: cannot find KM_TAG_ALGORITHM tag\n", __func__, __LINE__);
        ret = KM_ERROR_UNSUPPORTED_ALGORITHM;
        goto out;
    }
    aml_key->algo = algo;
    /* Generate Key based on input param and fills info into output data structure */
    if (KM_ALGORITHM_RSA == algo) {
        keymaster_rsa_keygen_params_t rsa_params;
        memset(&rsa_params, 0, sizeof(keymaster_rsa_keygen_params_t));
        if (!authorizations.GetTagValue(TAG_RSA_PUBLIC_EXPONENT, &rsa_params.public_exponent)) {
            LOG_D("%s", "No public exponent specified for RSA key generation");
            return KM_ERROR_INVALID_ARGUMENT;
        }

        if (!authorizations.GetTagValue(TAG_KEY_SIZE, &rsa_params.modulus_size)) {
            LOG_D("No key size specified for RSA key generation", 0);
            return KM_ERROR_UNSUPPORTED_KEY_SIZE;
        }

        ret = check_rsa_keygen_param(rsa_params.modulus_size, rsa_params.public_exponent);
        if (ret != KM_ERROR_OK) {
            LOG_D("%s:%d: check_rsa_keygen_param failed\n", __func__, __LINE__);
            goto out;
        }
        if (TEEC_SUCCESS != generate_rsa_keypair_ca(aml_key->handle, sizeof(aml_key->handle), &rsa_params)) {
            LOG_D("%s:%d: generate_rsa_keypair failed: mod: %u, exp: %llu\n", __func__, __LINE__, rsa_params.modulus_size, rsa_params.public_exponent);
            ret = KM_ERROR_UNKNOWN_ERROR;
            goto out;
        }
        aml_key->key_len = rsa_params.modulus_size;
        aml_key->optee_obj_type = TEE_TYPE_RSA_KEYPAIR;
    } else if (KM_ALGORITHM_EC == algo) {
        keymaster_ec_keygen_params_t ec_params = {.field_size = 0};
        if (!authorizations.GetTagValue(TAG_KEY_SIZE, &ec_params.field_size)) {
            LOG_D("No key size specified for EC key generation", 0);
            return KM_ERROR_UNSUPPORTED_KEY_SIZE;
        }
        ret = check_ec_keygen_param(ec_params.field_size);
        if (ret != KM_ERROR_OK) {
            LOG_D("%s:%d: check_ec_keygen_param failed\n", __func__, __LINE__);
            goto out;
        }
        if (TEEC_SUCCESS != generate_ec_keypair(aml_key->handle, sizeof(aml_key->handle), &ec_params)) {
            LOG_D("%s:%d: generate_ec_keypair failed\n", __func__, __LINE__);
            ret = KM_ERROR_UNKNOWN_ERROR;
            goto out;
        }
        aml_key->key_len = ec_params.field_size;
        aml_key->optee_obj_type = TEE_TYPE_ECDSA_KEYPAIR;
    } else if (KM_ALGORITHM_AES == algo) {
        if (TEEC_SUCCESS != generate_symmetric_key(aml_key->handle, sizeof(aml_key->handle),
                    aml_key->key_len, TEE_TYPE_AES)) {
            LOG_D("%s:%d: generate_symmetric_key failed\n", __func__, __LINE__);
            ret = KM_ERROR_UNKNOWN_ERROR;
            goto out;
        }
        aml_key->optee_obj_type = TEE_TYPE_AES;
    } else if (KM_ALGORITHM_HMAC == algo) {
        uint32_t dgst = 0;
        if (!key_blob || !hw_enforced || !sw_enforced)
            return KM_ERROR_OUTPUT_PARAMETER_NULL;

        uint32_t key_size_bits = 0;
        if (!key_description.GetTagValue(TAG_KEY_SIZE, &key_size_bits) ||
                !hmac_key_size_supported(key_size_bits))
            return KM_ERROR_UNSUPPORTED_KEY_SIZE;

        keymaster_digest_t digest;
        if (!key_description.GetTagValue(TAG_DIGEST, &digest)) {
            LOG_E("%d digests specified for HMAC key", key_description.GetTagCount(TAG_DIGEST));
            return KM_ERROR_UNSUPPORTED_DIGEST;
        }

        keymaster_error_t error = validate_hmac_key_params(key_description);
        if (error != KM_ERROR_OK)
            return error;
        dgst = android_digest_to_optee(digest);
        if (!dgst)
            return KM_ERROR_UNSUPPORTED_DIGEST;
        else
            aml_key->optee_obj_type = TEE_OBJECT_TYPE_ALGO(dgst);
        if (TEEC_SUCCESS != generate_symmetric_key(aml_key->handle, sizeof(aml_key->handle),
                    key_size_bits, aml_key->optee_obj_type)) {
            LOG_E("generate_symmetric_key failed: %d %x\n", key_size_bits, aml_key->optee_obj_type);
            goto out;
        }
        aml_key->key_len = key_size_bits;
    } else {
        LOG_D("%s:%d: Unsupport key type\n", __func__, __LINE__);
        goto out;
    }
    key_material.Reset(sizeof(aml_keyblob_t));
    memcpy(key_material.writable_data(), aml_key, sizeof(aml_keyblob_t));
    if (!key_material.key_material)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    ret = AmlCreateKeyBlob(authorizations, KM_ORIGIN_GENERATED,
            key_material, key_blob,
            hw_enforced,
            sw_enforced);
out:
    key_material.release();
    return ret;
}

keymaster_error_t KM1_export_key(const uint8_t *id, uint32_t id_len,
        uint32_t obj_type, uint32_t key_len,
		uint8_t** x509_data, size_t* x509_data_len)
{
    TEEC_Result res = TEEC_SUCCESS;
    keymaster_error_t error = KM_ERROR_OK;

    res = export_key(id, id_len, obj_type, key_len, x509_data, x509_data_len);
    if (res != TEEC_SUCCESS) {
        error = KM_ERROR_INVALID_KEY_BLOB;
    }
    return error;
}

/*
 * RSA Algorithm Table
 */
typedef struct algo_table_entry{
    keymaster_algorithm_t android_algo;
    keymaster_padding_t padding;
    keymaster_digest_t digest;
    uint32_t optee_algo;
} rsa_algo_table_entry_t;

rsa_algo_table_entry_t rsa_algo_table[] =
{
    {KM_ALGORITHM_RSA, KM_PAD_NONE, KM_DIGEST_NONE,
        TEE_ALG_RSA_NOPAD},

    {KM_ALGORITHM_RSA, KM_PAD_RSA_PKCS1_1_5_SIGN, KM_DIGEST_NONE,
        TEE_ALG_RSASSA_PKCS1_V1_5_NODIGEST},

    {KM_ALGORITHM_RSA, KM_PAD_RSA_PKCS1_1_5_SIGN, KM_DIGEST_MD5,
        TEE_ALG_RSASSA_PKCS1_V1_5_MD5},

    {KM_ALGORITHM_RSA, KM_PAD_RSA_PKCS1_1_5_SIGN, KM_DIGEST_SHA1,
        TEE_ALG_RSASSA_PKCS1_V1_5_SHA1},

    {KM_ALGORITHM_RSA, KM_PAD_RSA_PKCS1_1_5_SIGN, KM_DIGEST_SHA_2_224,
        TEE_ALG_RSASSA_PKCS1_V1_5_SHA224},

    {KM_ALGORITHM_RSA, KM_PAD_RSA_PKCS1_1_5_SIGN, KM_DIGEST_SHA_2_256,
        TEE_ALG_RSASSA_PKCS1_V1_5_SHA256},

    {KM_ALGORITHM_RSA, KM_PAD_RSA_PKCS1_1_5_SIGN, KM_DIGEST_SHA_2_384,
        TEE_ALG_RSASSA_PKCS1_V1_5_SHA384},

    {KM_ALGORITHM_RSA, KM_PAD_RSA_PKCS1_1_5_SIGN, KM_DIGEST_SHA_2_512,
        TEE_ALG_RSASSA_PKCS1_V1_5_SHA512},

    {KM_ALGORITHM_RSA, KM_PAD_RSA_PSS, KM_DIGEST_SHA1,
        TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1},

    {KM_ALGORITHM_RSA, KM_PAD_RSA_PSS, KM_DIGEST_SHA_2_224,
        TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224},

    {KM_ALGORITHM_RSA, KM_PAD_RSA_PSS, KM_DIGEST_SHA_2_256,
        TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256},

    {KM_ALGORITHM_RSA, KM_PAD_RSA_PSS, KM_DIGEST_SHA_2_384,
        TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384},

    {KM_ALGORITHM_RSA, KM_PAD_RSA_PSS, KM_DIGEST_SHA_2_512,
        TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512},

    {KM_ALGORITHM_RSA, KM_PAD_RSA_PKCS1_1_5_ENCRYPT, KM_DIGEST_NONE,
        TEE_ALG_RSAES_PKCS1_V1_5},

    {KM_ALGORITHM_RSA, KM_PAD_RSA_OAEP, KM_DIGEST_SHA1,
        TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1},

    {KM_ALGORITHM_RSA, KM_PAD_RSA_OAEP, KM_DIGEST_SHA_2_224,
        TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224},

    {KM_ALGORITHM_RSA, KM_PAD_RSA_OAEP, KM_DIGEST_SHA_2_256,
        TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256},

    {KM_ALGORITHM_RSA, KM_PAD_RSA_OAEP, KM_DIGEST_SHA_2_384,
        TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384},

    {KM_ALGORITHM_RSA, KM_PAD_RSA_OAEP, KM_DIGEST_SHA_2_512,
        TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512},

    //TODO: what is TEE_ALG_RSASSA_PKCS1_V1_5_MD5SHA1 mapping?
};
const uint32_t rsa_algo_table_size = sizeof(rsa_algo_table) / sizeof(rsa_algo_table_entry_t);

/*
 * AES Algorithm Table
 */
typedef struct {
    keymaster_algorithm_t android_algo;
    keymaster_padding_t padding;
    keymaster_block_mode_t block_mode;
    uint32_t optee_algo;
} aes_algo_table_entry_t;

aes_algo_table_entry_t aes_algo_table[] =
{
    {KM_ALGORITHM_AES, KM_PAD_NONE, KM_MODE_ECB, TEE_ALG_AES_ECB_NOPAD},
    {KM_ALGORITHM_AES, KM_PAD_NONE, KM_MODE_CBC, TEE_ALG_AES_CBC_NOPAD},
    {KM_ALGORITHM_AES, KM_PAD_NONE, KM_MODE_CTR, TEE_ALG_AES_CTR},
    /*TODO: what is TEE_ALG_AES_CTS mapping? */
    /*TODO: what is TEE_ALG_AES_XTS mapping? */
    /*TODO: what is TEE_ALG_AES_CBC_MAC_NOPAD mapping? */
    /*TODO: what is TEE_ALG_AES_CBC_MAC_PKCS5 mapping? */
    /*TODO: what is TEE_ALG_AES_CCM mapping? */
    {KM_ALGORITHM_AES, KM_PAD_NONE, KM_MODE_GCM, TEE_ALG_AES_GCM},
};
const uint32_t aes_algo_table_size = sizeof(aes_algo_table) / sizeof(aes_algo_table_entry_t);

static TEEC_Result map_android_algo_to_optee(const keymaster_algorithm_t android_algo,
        uint32_t key_len,
        const keymaster_digest_t digest,
        const keymaster_padding_t padding,
        const uint32_t block_mode,
        uint32_t* optee_algo)
{
    uint32_t i = 0;
    TEEC_Result ret = TEEC_ERROR_NOT_SUPPORTED;
    //__android_log_write(ANDROID_LOG_DEBUG, LOG_TAG, "map_android_algo_to_optee");
    if (optee_algo == NULL) {
        LOG_D("%s: %d, invalid input: %d\n", __FUNCTION__, __LINE__);
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    if (android_algo == KM_ALGORITHM_RSA) {
        for (i = 0; i < rsa_algo_table_size ; i++) {
            if (rsa_algo_table[i].digest == digest &&
                    rsa_algo_table[i].padding == padding) {
                *optee_algo = rsa_algo_table[i].optee_algo;
                ret = TEEC_SUCCESS;
                break;
            }
        }
    } else if (android_algo == KM_ALGORITHM_EC) {
        switch (key_len) {
            case 192:
                *optee_algo = TEE_ALG_ECDSA_P192;
                ret = TEEC_SUCCESS;
                break;
            case 224:
                *optee_algo = TEE_ALG_ECDSA_P224;
                ret = TEEC_SUCCESS;
                break;
            case 256:
                *optee_algo = TEE_ALG_ECDSA_P256;
                ret = TEEC_SUCCESS;
                break;
            case 384:
                *optee_algo = TEE_ALG_ECDSA_P384;
                ret = TEEC_SUCCESS;
                break;
            case 521:
                *optee_algo = TEE_ALG_ECDSA_P521;
                ret = TEEC_SUCCESS;
                break;
            default:
                break;
        }
    } else if (android_algo == KM_ALGORITHM_AES) {
        for (i = 0; i < aes_algo_table_size ; i++) {
            if (/*aes_algo_table[i].padding == padding &&*/
                    aes_algo_table[i].block_mode == (keymaster_block_mode_t)block_mode) {
                *optee_algo = aes_algo_table[i].optee_algo;
                ret = TEEC_SUCCESS;
                break;
            }
        }
    } else if (android_algo == KM_ALGORITHM_HMAC) {
        switch (digest) {
            case KM_DIGEST_MD5:
                *optee_algo = TEE_ALG_HMAC_MD5;
                ret = TEEC_SUCCESS;
                break;
            case KM_DIGEST_SHA1:
                *optee_algo = TEE_ALG_HMAC_SHA1;
                ret = TEEC_SUCCESS;
                break;
            case KM_DIGEST_SHA_2_224:
                *optee_algo = TEE_ALG_HMAC_SHA224;
                ret = TEEC_SUCCESS;
                break;
            case KM_DIGEST_SHA_2_256:
                *optee_algo = TEE_ALG_HMAC_SHA256;
                ret = TEEC_SUCCESS;
                break;
            case KM_DIGEST_SHA_2_384:
                *optee_algo = TEE_ALG_HMAC_SHA384;
                ret = TEEC_SUCCESS;
                break;
            case KM_DIGEST_SHA_2_512:
                *optee_algo = TEE_ALG_HMAC_SHA512;
                ret = TEEC_SUCCESS;
                break;
            case KM_DIGEST_NONE:
                break;
        }
    }
    if (ret != TEEC_SUCCESS) {
        LOG_D("android_algo(%u)\n", android_algo);
        LOG_D("digest(%u)\n", digest);
        LOG_D("padding(%u)\n", padding);
    }
    return ret;
}

static TEEC_Result map_android_purpose_to_optee_mode(const uint32_t optee_algo,
        const keymaster_purpose_t purpose,
        TEE_OperationMode* op_mode)
{
    if (op_mode == NULL)
        return TEEC_ERROR_GENERIC;

    if (optee_algo == TEE_ALG_RSA_NOPAD) {
        if (purpose == KM_PURPOSE_SIGN)
            *op_mode = TEE_MODE_DECRYPT;
        else if (purpose == KM_PURPOSE_VERIFY)
            *op_mode = TEE_MODE_ENCRYPT;
        else
            *op_mode = (TEE_OperationMode)purpose;
    } else {
        /* make sure the order of android enum is the same as that of optee */
        *op_mode = (TEE_OperationMode)purpose;
        //op_mode = TEE_MODE_SIGN;
    }
    return TEEC_SUCCESS;
}

keymaster_error_t KM1_digest_init(keymaster_algorithm_t android_algo,
        uint32_t key_len,
        keymaster_digest_t digest,
        keymaster_padding_t padding,
        TEE_OperationHandle* digest_op)
{
    keymaster_error_t ret = KM_ERROR_OK;
    TEEC_Result res = TEEC_ERROR_GENERIC;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    uint32_t optee_algo;
    uint32_t hash_algo = TEE_ALG_SHA1;

    if (digest_op == TEE_HANDLE_NULL) {
        LOG_D("%s:%d: invalid input.\n", __func__, __LINE__);
        ret = KM_ERROR_INVALID_OPERATION_HANDLE;
        goto out;
    }

    res = map_android_algo_to_optee(android_algo, key_len, digest, padding, 0, &optee_algo);
    if (res != TEEC_SUCCESS) {
        LOG_D("map_android_algo_to_optee failed(%x)\n", res);
        ret = KM_ERROR_UNSUPPORTED_ALGORITHM;
        goto out;
    }
    switch (digest) {
        case KM_DIGEST_MD5:
            hash_algo = TEE_ALG_MD5;
        case KM_DIGEST_SHA1:
            hash_algo = TEE_ALG_SHA1;
            break;
        case KM_DIGEST_SHA_2_224:
            hash_algo  = TEE_ALG_SHA224;
            break;
        case KM_DIGEST_SHA_2_256:
            hash_algo  = TEE_ALG_SHA256;
            break;
        case KM_DIGEST_SHA_2_384:
            hash_algo = TEE_ALG_SHA384;
            break;
        case KM_DIGEST_SHA_2_512:
            hash_algo = TEE_ALG_SHA512;
            break;
        case KM_DIGEST_NONE:
            hash_algo = TEE_ALG_SHA1;
            break;
    }

    res = digest_init_ca(optee_algo, &op, hash_algo);
    if (res != TEEC_SUCCESS) {
        LOG_D(" digest_init_ca failed(%x)\n", res);
        ret = KM_ERROR_UNSUPPORTED_ALGORITHM;
        goto out;
    }

    *digest_op = op;
out:
    return ret;
}

keymaster_error_t KM1_digest_update(TEE_OperationHandle digest_op,
        const void* chunk,
        size_t chunk_len)
{
    keymaster_error_t ret = KM_ERROR_OK;
    TEEC_Result res = TEEC_ERROR_GENERIC;

    if (digest_op == TEE_HANDLE_NULL) {
        LOG_D("%s:%d: invalid input\n", __func__, __LINE__);
        ret = KM_ERROR_INVALID_OPERATION_HANDLE;
        goto out;
    }

    res = digest_update_ca(digest_op, chunk, chunk_len);
    if (res != TEEC_SUCCESS) {
        LOG_D("digest_update_ca failed(%x)\n", res);
        ret = KM_ERROR_UNSUPPORTED_DIGEST;
    }
out:
    return ret;
}

keymaster_error_t KM1_digest_final(TEE_OperationHandle digest_op,
        const void* chunk, size_t chunk_len,
        void* hash, size_t* hash_len)
{
    keymaster_error_t ret = KM_ERROR_OK;
    TEEC_Result res = TEEC_ERROR_GENERIC;

    if (digest_op == TEE_HANDLE_NULL) {
        LOG_D("%s:%d: invalid input\n", __func__, __LINE__);
        ret = KM_ERROR_INVALID_OPERATION_HANDLE;
        goto out;
    }

    res = digest_do_final_ca(digest_op, chunk, chunk_len, hash, hash_len);
    if (res != TEEC_SUCCESS) {
        LOG_D("digest_do_final_ca failed(%x)\n", res);
        ret = KM_ERROR_UNSUPPORTED_DIGEST;
    }

out:
    return ret;
}

keymaster_error_t KM1_hmac_keyblob_init(
        keymaster_algorithm_t android_algo,
        keymaster_digest_t digest,
        TEE_OperationHandle* operation)
{
    keymaster_error_t ret = KM_ERROR_OK;
    TEEC_Result res = TEEC_ERROR_GENERIC;
    uint32_t optee_algo = 0;
	uint32_t optee_obj_type;
	uint32_t dgst = 0;

    if (!operation) {
        LOG_D("%s:%d: invalid output.\n", __func__, __LINE__);
        ret = KM_ERROR_OUTPUT_PARAMETER_NULL;
        goto out;
    }

    res = map_android_algo_to_optee(android_algo, 0, digest, KM_PAD_NONE, 0, &optee_algo);
    if (res != TEEC_SUCCESS) {
        LOG_D("map_android_algo_to_optee failed(%x)\n", res);
        ret = KM_ERROR_UNSUPPORTED_ALGORITHM;
        goto out;
    }
	dgst = android_digest_to_optee(digest);
	if (!dgst)
		return KM_ERROR_UNSUPPORTED_DIGEST;
	else
		optee_obj_type = TEE_OBJECT_TYPE_ALGO(dgst);
	res = hmac_keyblob_init_ca(optee_algo, optee_obj_type, operation);
    if (res != TEEC_SUCCESS) {
        LOG_D("hmac_keyblob_init_ca failed(%x) algo: %x, type: %x\n", res, optee_algo, optee_obj_type);
        ret = KM_ERROR_UNSUPPORTED_ALGORITHM;
        goto out;
    }

out:
    return ret;
}
keymaster_error_t KM1_hmac_init(
        TEE_ObjectHandle key,
        uint32_t key_len,
        keymaster_algorithm_t android_algo,
        keymaster_digest_t digest,
        TEE_OperationHandle* operation)
{
    keymaster_error_t ret = KM_ERROR_OK;
    TEEC_Result res = TEEC_ERROR_GENERIC;
    uint32_t optee_algo = 0;

    if (!operation) {
        LOG_D("%s:%d: invalid output.\n", __func__, __LINE__);
        ret = KM_ERROR_OUTPUT_PARAMETER_NULL;
        goto out;
    }

    res = map_android_algo_to_optee(android_algo, key_len, digest, KM_PAD_NONE, 0, &optee_algo);
    if (res != TEEC_SUCCESS) {
        LOG_D("map_android_algo_to_optee failed(%x)\n", res);
        ret = KM_ERROR_UNSUPPORTED_ALGORITHM;
        goto out;
    }

    res = hmac_init_ca(optee_algo, operation, key, key_len);
    if (res != TEEC_SUCCESS) {
        LOG_D("hmac_init_ca failed(%x) len: %d\n", res, key_len);
        ret = KM_ERROR_UNSUPPORTED_ALGORITHM;
        goto out;
    }

out:
    return ret;
}

keymaster_error_t KM1_hmac_update(
        TEE_OperationHandle hmac_op,
        const void* chunk,
        size_t chunk_len)
{
    keymaster_error_t ret = KM_ERROR_OK;
    TEEC_Result res = TEEC_ERROR_GENERIC;

    if (hmac_op == TEE_HANDLE_NULL) {
        LOG_D("%s:%d: invalid input\n", __func__, __LINE__);
        ret = KM_ERROR_INVALID_OPERATION_HANDLE;
        goto out;
    }

    res = hmac_update_ca(hmac_op, chunk, chunk_len);
    if (res != TEEC_SUCCESS) {
        LOG_D("hmac_update_ca failed(%x)\n", res);
        ret = KM_ERROR_UNSUPPORTED_DIGEST;
    }
out:
    return ret;
}

keymaster_error_t KM1_hmac_final(
        TEE_OperationHandle hmac_op,
        const void* chunk, size_t chunk_len,
        void* hash, size_t* hash_len)
{
    keymaster_error_t ret = KM_ERROR_OK;
    TEEC_Result res = TEEC_ERROR_GENERIC;

    if (hmac_op == TEE_HANDLE_NULL) {
        LOG_D("%s:%d: invalid input\n", __func__, __LINE__);
        ret = KM_ERROR_INVALID_OPERATION_HANDLE;
        goto out;
    }

    res = hmac_do_final_ca(hmac_op, chunk, chunk_len, hash, hash_len);
    if (res != TEEC_SUCCESS) {
        LOG_D("hmac_do_final_ca failed(%x)\n", res);
        ret = KM_ERROR_UNSUPPORTED_DIGEST;
    }

out:
    return ret;
}

keymaster_error_t KM1_hmac_final_compare(
        TEE_OperationHandle hmac_op,
        const void* chunk, size_t chunk_len,
        const void* hash, size_t hash_len)
{
    keymaster_error_t ret = KM_ERROR_OK;
    TEEC_Result res = TEEC_ERROR_GENERIC;

    if (hmac_op == TEE_HANDLE_NULL) {
        LOG_D("%s:%d: invalid input\n", __func__, __LINE__);
        ret = KM_ERROR_INVALID_OPERATION_HANDLE;
        goto out;
    }

    res = hmac_do_final_compare_ca(hmac_op, chunk, chunk_len, hash, hash_len);
    if (res != TEEC_SUCCESS) {
        LOG_D("hmac_do_final_compare_ca failed(%x), len: %d\n", res, hash_len);
        ret = KM_ERROR_VERIFICATION_FAILED;
    }

out:
    return ret;
}

keymaster_error_t KM1_allocate_operation(
        TEE_ObjectHandle key, uint32_t key_len,
        keymaster_algorithm_t android_algo,
        keymaster_purpose_t purpose,
        keymaster_digest_t digest, keymaster_padding_t padding,
        keymaster_block_mode_t block_mode,
        TEE_OperationHandle* operation,
        TEE_OperationMode* operation_mode)
{
    keymaster_error_t ret = KM_ERROR_OK;
    TEEC_Result res = TEEC_ERROR_GENERIC;
    uint32_t optee_algo;
    TEE_OperationMode op_mode;
    TEE_OperationHandle op = TEE_HANDLE_NULL;

    if (!operation || !operation_mode) {
        LOG_D("operation is null: %p %p\n", operation, operation_mode);
        ret = KM_ERROR_OUTPUT_PARAMETER_NULL;
        goto out;
    }

    res = map_android_algo_to_optee(android_algo, key_len, digest, padding, block_mode, &optee_algo);
    if (res != TEEC_SUCCESS) {
        LOG_D("map_android_algo_to_optee failed(%x)\n", res);
        ret = KM_ERROR_UNSUPPORTED_ALGORITHM;
        goto out;
    }
    res = map_android_purpose_to_optee_mode(optee_algo, purpose, &op_mode);
    if (res != TEEC_SUCCESS) {
        LOG_D("map_android_purpose_to_optee_mode failed(%x)\n", res);
        ret = KM_ERROR_UNSUPPORTED_PURPOSE;
        goto out;
    }

    res = allocate_operation(&op, optee_algo, op_mode, key_len);
    if (res != TEEC_SUCCESS) {
        LOG_D("allocate_operation(sign) failed with res(%x)\n", res);
        ret = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        goto out;
    }

    res = set_operation_key(op, key);
    if (res != TEEC_SUCCESS) {
        LOG_D("set_operation_key failed with res(%x)\n", res);
        ret = KM_ERROR_UNKNOWN_ERROR;
        goto out;
    }

    *operation = op;
    *operation_mode = op_mode;
out:
    return ret;
}

keymaster_error_t KM1_asymmetric_sign_with_handle(
        TEE_OperationHandle op, TEE_OperationMode op_mode,
        const uint8_t* digest, const size_t digest_len,
        uint8_t* sig, size_t* sig_len)
{
    keymaster_error_t ret = KM_ERROR_OK;
    TEEC_Result res = TEEC_ERROR_GENERIC;
    TEE_Attribute algo_params[4];
    size_t num_algo_params = 0;

    /* Add TEE_ATTR_ASN1_ENCODED */
    add_attr_value(&num_algo_params, algo_params, TEE_ATTR_ASN1_ENCODED, 1, 0);

    /* Add TEE_ATTR_RSA_PSS_SALT_LENGTH */
    add_attr_value(&num_algo_params, algo_params, TEE_ATTR_RSA_PSS_SALT_LENGTH,
            SALT_LEN, 0);

    if (op_mode == TEE_MODE_DECRYPT || op_mode == TEE_MODE_SIGN) {
        res = asymmetric_sign_tee_ca(op, op_mode,
                algo_params, num_algo_params, digest,
                digest_len, sig, sig_len);
    }
    else {
        res = TEEC_ERROR_NOT_SUPPORTED;
    }

    if (res != TEEC_SUCCESS) {
        LOG_D("op_mode (%x)\n", op_mode);
        LOG_D("digest_len(%d)\n", digest_len);
        LOG_D("preallocate buffer for sig, size=(%d)\n", *sig_len);
        LOG_D("asymmetric_sign_tee_ca failed with res(%x)\n", res);
        ret = KM_ERROR_INVALID_ARGUMENT;
        goto out;
    }
out:
    return ret;
}

keymaster_error_t KM1_asymmetric_verify_with_handle(
        TEE_OperationHandle op, TEE_OperationMode op_mode,
        const uint8_t* digest, const size_t digest_len,
        const uint8_t* sig, const size_t sig_len)
{
    keymaster_error_t ret = KM_ERROR_OK;
    TEEC_Result res = TEEC_ERROR_GENERIC;
    TEE_Attribute algo_params[4];
    size_t num_algo_params = 0;

    /* Add TEE_ATTR_ASN1_ENCODED */
    add_attr_value(&num_algo_params, algo_params, TEE_ATTR_ASN1_ENCODED, 1, 0);

    /* Add TEE_ATTR_RSA_PSS_SALT_LENGTH */
    add_attr_value(&num_algo_params, algo_params, TEE_ATTR_RSA_PSS_SALT_LENGTH,
           digest_len, 0);

    if (op_mode == TEE_MODE_ENCRYPT || op_mode == TEE_MODE_VERIFY) {
        res = asymmetric_verify_tee_ca(op, op_mode,
                algo_params, num_algo_params, digest,
                digest_len, sig, sig_len);
    }
    else {
        res = TEEC_ERROR_NOT_SUPPORTED;
    }

    if (res != TEEC_SUCCESS) {
        LOG_D("%s:%d: op_mode (%x)\n", __func__, __LINE__, op_mode);
        LOG_D("%s:%d: digest_len(%d)\n", __func__, __LINE__, digest_len);
        LOG_D("%s:%d: sig_len(%d)\n", __func__, __LINE__, sig_len);
        LOG_D("asymmetric_verify_tee_ca failed with res(%x)\n", res);
        ret = KM_ERROR_VERIFICATION_FAILED;
    }

    return ret;
}

keymaster_error_t KM1_asymmetric_en_de_crypt_with_handle(
        TEE_OperationHandle op, TEE_OperationMode op_mode,
        const uint8_t* digest, const size_t digest_len,
        uint8_t* sig, size_t* sig_len)
{
    keymaster_error_t ret = KM_ERROR_OK;
    TEEC_Result res = TEEC_ERROR_GENERIC;
    TEE_Attribute algo_params[4];
    size_t num_algo_params = 0;

    /* Add TEE_ATTR_ASN1_ENCODED */
    add_attr_value(&num_algo_params, algo_params, TEE_ATTR_ASN1_ENCODED, 1, 0);

    /* This attribute forces mgf1 in OAEP encrypt default to SHA-1 */
    add_attr_value(&num_algo_params, algo_params, TEE_ATTR_RSA_OAEP_MGF1_USE_SHA1,
            1, 0);

    res = asymmetric_en_de_crypt_tee_ca(op, op_mode,
            algo_params, num_algo_params, digest,
            digest_len, sig, sig_len);

    if (res != TEEC_SUCCESS) {
        LOG_D("op_mode (%x)\n", op_mode);
        LOG_D("digest_len(%d)\n", digest_len);
        switch (res) {
            case TEE_ERROR_ARGUMENT_INVALID:
                LOG_D("asymmetric_sign_tee_ca failed with TEE_ERROR_ARGUMENT_INVALID(%x)\n", res);
                ret = KM_ERROR_INVALID_ARGUMENT;
                break;
            case TEE_ERROR_INPUT_LENGTH_INVALID:
                LOG_D("asymmetric_sign_tee_ca failed with TEE_ERROR_INPUT_LENGTH_INVALID(%x)\n", res);
                ret = KM_ERROR_INVALID_INPUT_LENGTH;
                break;
            default:
                LOG_D("asymmetric_sign_tee_ca failed with res(%x)\n", res);
                ret = KM_ERROR_UNKNOWN_ERROR;
                break;
        }
        goto out;
    }
out:
    return ret;
}

keymaster_error_t KM1_import_symmetric_key(
        keymaster_algorithm_t algorithm,
        const AuthorizationSet& key_description,
        const uint8_t* key, const size_t key_len,
        aml_keyblob_t* aml_key)
{
    TEE_Result res = TEEC_ERROR_GENERIC;
    keymaster_error_t ret = KM_ERROR_OK; /* Default */
    uint32_t dgst = 0;

    /* Sanity Check */
    if (false == get_ca_inited()) {
        if (KM_Secure_Initialize() < 0) {
            LOG_D("%s:%d: KM_Secure_Initialize failed ...\n", __func__, __LINE__);
            ret = KM_ERROR_UNKNOWN_ERROR;
            goto out;
        }
    }

    if (algorithm == KM_ALGORITHM_HMAC) {
        keymaster_digest_t digest;
        if (!key_description.GetTagValue(TAG_DIGEST, &digest)) {
            LOG_E("%d digests specified for HMAC key", key_description.GetTagCount(TAG_DIGEST));
            ret = KM_ERROR_UNSUPPORTED_DIGEST;
            goto out;
        }
        /* Generate Keypair */
        dgst = android_digest_to_optee(digest);
        if (!dgst)
            return KM_ERROR_UNSUPPORTED_DIGEST;
        else
            aml_key->optee_obj_type = TEE_OBJECT_TYPE_ALGO(dgst);
    } else if (algorithm == KM_ALGORITHM_AES) {
        aml_key->optee_obj_type = TEE_TYPE_AES;
    } else {
        assert(0);
    }

    aml_key->key_len = key_len * 8;
    res = do_import_symmetric_key_tee_ca(key, key_len, aml_key->optee_obj_type,
            aml_key->handle, sizeof(aml_key->handle));
    if (res != TEEC_SUCCESS) {
        LOG_D("do_import_symmetric_key_tee_ca: %x %x\n", res, aml_key->optee_obj_type);
        ret = KM_ERROR_UNKNOWN_ERROR;
        goto out;
    }
out:
    return ret;
}

keymaster_error_t KM1_cipher_init(const TEE_OperationHandle op,
        const void *iv, const size_t iv_len)
{
    keymaster_error_t ret = KM_ERROR_OK;
    TEEC_Result res = TEEC_SUCCESS;

    res = cipher_init_ca(op, iv, iv_len);
    if (res != TEEC_SUCCESS) {
        LOG_D("%s:%d: cipher init fail(%x)\n", __func__, __LINE__, res);
        ret = KM_ERROR_UNKNOWN_ERROR;
        goto out;
    }
    ret = KM_ERROR_OK;
out:
    return ret;
}

keymaster_error_t KM1_cipher_update(TEE_OperationHandle oph,
        const void *src, size_t src_len,
        void *dst, size_t *dst_len, const uint32_t need_buffering)
{
    TEEC_Result res;
    keymaster_error_t ret = KM_ERROR_OK;
	res = cipher_update_ca(oph, src, src_len, dst, dst_len, need_buffering);
    if (res != TEEC_SUCCESS) {
        LOG_D("%s:%d: cipher_update fail(%x)\n", __func__, __LINE__, res);
        ret = KM_ERROR_UNKNOWN_ERROR;
        goto out;
    }
    ret = KM_ERROR_OK;
out:
    return ret;
}

keymaster_error_t KM1_cipher_do_final(TEE_OperationHandle oph,
        const void *src, size_t src_len,
        void *dst, size_t *dst_len)
{
    TEEC_Result res;
    keymaster_error_t ret = KM_ERROR_OK;

    res = cipher_do_final_ca(oph, src, src_len, dst, dst_len);
    if (res != TEEC_SUCCESS) {
        LOG_D("%s:%d:  cipher_do_final_ca fail(%x): %u, %u\n", __func__, __LINE__, res, src_len, *dst_len);
        ret = KM_ERROR_UNKNOWN_ERROR;
        goto out;
    }
    ret = KM_ERROR_OK;
out:
    return ret;
}

keymaster_error_t KM1_ae_init(const TEE_OperationHandle op,
        const void *nonce, size_t nonce_len,
        size_t tag_len, size_t aad_len,
        size_t payload_len)
{
    keymaster_error_t error = KM_ERROR_OK;
    TEEC_Result res = TEEC_SUCCESS;

    res = tee_ae_init(op, nonce, nonce_len, tag_len, aad_len, payload_len);
    if (res != TEEC_SUCCESS) {
        LOG_E("KM1_ae_init: failed: %zd, %zd, %zd, %zd", nonce_len, tag_len, aad_len, payload_len);
        error = KM_ERROR_UNKNOWN_ERROR;
        goto out;
    }
out:
    return error;
}

keymaster_error_t KM1_ae_update_aad(const TEE_OperationHandle handle,
        const void *aad, size_t aad_len)
{
    TEEC_Result res = TEEC_SUCCESS;
    keymaster_error_t error = KM_ERROR_OK;

    res = tee_ae_update_aad(handle, aad, aad_len);
    if (res != TEEC_SUCCESS) {
        error = KM_ERROR_UNKNOWN_ERROR;
    }
    return error;
}

keymaster_error_t KM1_ae_update(const TEE_OperationHandle handle,
        const void *src, size_t src_len,
        void *dst, size_t *dst_len,
        const uint32_t need_buffering)
{
    TEEC_Result res = TEEC_SUCCESS;
    keymaster_error_t error = KM_ERROR_OK;

    res = tee_ae_update(handle, src, src_len, dst, dst_len, need_buffering);
    if (res != TEEC_SUCCESS) {
        error = KM_ERROR_UNKNOWN_ERROR;
    }
    return error;
}

keymaster_error_t KM1_ae_encrypt_final(const TEE_OperationHandle handle,
        const void *src, size_t src_len,
        void *dst, size_t *dst_len,
        void *tag, size_t *tag_len)
{
    TEEC_Result res = TEEC_SUCCESS;
    keymaster_error_t error = KM_ERROR_OK;

    res = tee_ae_encrypt_final(handle, src, src_len, dst, dst_len, tag, tag_len);
    if (res != TEEC_SUCCESS) {
        error = KM_ERROR_UNKNOWN_ERROR;
    }
    return error;
}

keymaster_error_t KM1_ae_decrypt_final(
        const TEE_OperationHandle handle,
        const void *src, size_t src_len,
        void *dst, size_t *dst_len,
        const void *tag, size_t tag_len)
{
    TEEC_Result res = TEEC_SUCCESS;
    keymaster_error_t error = KM_ERROR_OK;

    res = tee_ae_decrypt_final(handle, src, src_len, dst, dst_len, tag, tag_len);
    if (res != TEEC_SUCCESS) {
        if (res == TEE_ERROR_MAC_INVALID)
            error = KM_ERROR_VERIFICATION_FAILED;
        else
            error = KM_ERROR_UNKNOWN_ERROR;
    }
    return error;
}

keymaster_error_t KM1_free_operation(const TEE_OperationHandle handle)
{
    TEEC_Result res = TEEC_SUCCESS;

    if (handle) {
        res = free_operation((TEE_OperationHandle)handle);
	}
    else
        return KM_ERROR_INVALID_OPERATION_HANDLE;

    if (res != TEEC_SUCCESS)
        return KM_ERROR_INVALID_OPERATION_HANDLE;
    else
        return KM_ERROR_OK;
}

keymaster_error_t KM1_delete_key(const uint8_t *handle, uint32_t len)
{
    TEEC_Result res = TEEC_SUCCESS;
    res = delete_key_ca(handle, len);
    if (res != TEEC_SUCCESS)
        return KM_ERROR_UNKNOWN_ERROR;
    return KM_ERROR_OK;
}

keymaster_error_t KM1_load_key(TEE_ObjectHandle *keyobj, const uint8_t *id, uint32_t id_len,
		uint32_t obj_type, uint32_t key_len)
{
    TEEC_Result res = TEEC_SUCCESS;
    res = load_key_ca(keyobj, id, id_len, obj_type, key_len);
    if (res != TEEC_SUCCESS)
        return KM_ERROR_UNKNOWN_ERROR;
    return KM_ERROR_OK;
}

keymaster_error_t KM1_release_key(TEE_ObjectHandle keyobj)
{
    TEEC_Result res = TEEC_SUCCESS;
	res = release_key_ca(keyobj);
    if (res != TEEC_SUCCESS)
        return KM_ERROR_UNKNOWN_ERROR;
    return KM_ERROR_OK;
}
