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


#include "aml_keymaster_context.h"
using std::unique_ptr;

static uint8_t master_key_bytes[AES_BLOCK_SIZE] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
const int NONCE_LENGTH = 12;
const int TAG_LENGTH = 16;
const KeymasterKeyBlob MASTER_KEY(master_key_bytes, array_length(master_key_bytes));

static keymaster_error_t AmlTranslateAuthorizationSetError(AuthorizationSet::Error err) {
	switch (err) {
		case AuthorizationSet::OK:
			return KM_ERROR_OK;
		case AuthorizationSet::ALLOCATION_FAILURE:
			return KM_ERROR_MEMORY_ALLOCATION_FAILED;
		case AuthorizationSet::MALFORMED_DATA:
			return KM_ERROR_UNKNOWN_ERROR;
	}
	return KM_ERROR_OK;
}

static keymaster_error_t AmlSetAuthorizations(const AuthorizationSet& key_description,
                                           keymaster_key_origin_t origin,
                                           AuthorizationSet* hw_enforced,
                                           AuthorizationSet* sw_enforced) {
    AuthorizationSet *enforced = nullptr;
    sw_enforced->Clear();
    hw_enforced->Clear();

    if (origin == KM_ORIGIN_GENERATED)
        enforced = hw_enforced;
    else
        enforced = sw_enforced;
    for (auto& entry : key_description) {
        switch (entry.tag) {
            // These cannot be specified by the client.
            case KM_TAG_ROOT_OF_TRUST:
            case KM_TAG_ORIGIN:
                LOG_E("Root of trust and origin tags may not be specified", 0);
                return KM_ERROR_INVALID_TAG;

                // These don't work.
            case KM_TAG_ROLLBACK_RESISTANT:
                LOG_E("KM_TAG_ROLLBACK_RESISTANT not supported", 0);
                return KM_ERROR_UNSUPPORTED_TAG;

                // These are hidden.
            case KM_TAG_APPLICATION_ID:
            case KM_TAG_APPLICATION_DATA:
                break;

            case KM_TAG_ALGORITHM:
            case KM_TAG_RSA_PUBLIC_EXPONENT:
            case KM_TAG_KEY_SIZE:
            case KM_TAG_DIGEST:
            case KM_TAG_PADDING:
                enforced->push_back(entry);
                break;
#if 0
            case KM_TAG_PURPOSE:
            case KM_TAG_BLOCK_MODE:
            case KM_TAG_CALLER_NONCE:
            case KM_TAG_MIN_MAC_LENGTH:
                if (hw_enforced->GetTagCount(entry.tag) == 0)
                    hw_enforced->push_back(entry);
                break;
#endif
                // Everything else we just copy into hw_enforced, unless the KeyFactory has placed it in
                // hw_enforced, in which case we defer to its decision.
            default:
                sw_enforced->push_back(entry);
                break;
        }
    }

    sw_enforced->push_back(TAG_CREATION_DATETIME, java_time(time(NULL)));
    enforced->push_back(TAG_ORIGIN, origin);
    return AmlTranslateAuthorizationSetError(sw_enforced->is_valid());
}

static keymaster_error_t AmlSetHwEnforced(const AuthorizationSet& key_description,
		const keymaster_key_origin_t origin,
		AuthorizationSet* hw_enforced)
{
	keymaster_error_t error = KM_ERROR_OK;
	keymaster_algorithm_t algorithm;
	uint64_t public_exponent;
	uint32_t key_size;
    keymaster_digest_t digest;
    keymaster_padding_t padding;

	if (!key_description.GetTagValue(TAG_ALGORITHM, &algorithm)) {
		error = KM_ERROR_UNSUPPORTED_ALGORITHM;
    } else if (origin == KM_ORIGIN_GENERATED) {
        hw_enforced->push_back(TAG_ALGORITHM, algorithm);
        if (key_description.GetTagValue(TAG_RSA_PUBLIC_EXPONENT, &public_exponent))
            hw_enforced->push_back(TAG_RSA_PUBLIC_EXPONENT, public_exponent);
        if (key_description.GetTagValue(TAG_KEY_SIZE, &key_size))
            hw_enforced->push_back(TAG_KEY_SIZE, key_size);
        if (key_description.GetTagValue(TAG_DIGEST, &digest))
            hw_enforced->push_back(TAG_DIGEST, digest);
        if (key_description.GetTagValue(TAG_PADDING, &padding))
            hw_enforced->push_back(TAG_PADDING, padding);
#if 0
        if (algorithm == KM_ALGORITHM_RSA) {
            /* public exponent */
            if (key_description.GetTagValue(TAG_RSA_PUBLIC_EXPONENT, &public_exponent)) {
                hw_enforced->push_back(TAG_RSA_PUBLIC_EXPONENT, public_exponent);
            }
            /* key size */
            if (key_description.GetTagValue(TAG_KEY_SIZE, &key_size)) {
                hw_enforced->push_back(TAG_KEY_SIZE, key_size);
            }
        }
        else if (algorithm == KM_ALGORITHM_EC) {
            /* key size */
            if (key_description.GetTagValue(TAG_KEY_SIZE, &key_size)) {
                hw_enforced->push_back(TAG_KEY_SIZE, key_size);
            }
        }
        else if (algorithm == KM_ALGORITHM_HMAC) {
        }
        else if (algorithm == KM_ALGORITHM_AES) {
        }
        else {
            error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        }
#endif
        hw_enforced->push_back(TAG_ORIGIN, origin);
    }

out:
	return error;
}

keymaster_error_t AmlCreateKeyBlob(
		const AuthorizationSet& key_description,
		const keymaster_key_origin_t origin,
		const KeymasterKeyBlob& key_material,
		KeymasterKeyBlob* blob,
		AuthorizationSet* hw_enforced,
		AuthorizationSet* sw_enforced) {

	keymaster_error_t error = KM_ERROR_OK;

	error = AmlSetAuthorizations(key_description, origin, hw_enforced, sw_enforced);
	if (error != KM_ERROR_OK)
		return error;

	AuthorizationSet hidden;
	error = AmlBuildHiddenAuthorizations(key_description, &hidden);
	if (error != KM_ERROR_OK)
		return error;

	return AmlSerializeIntegrityAssuredBlob(key_material, hidden, *hw_enforced, *sw_enforced, blob);
}

keymaster_error_t AmlParseKeyBlob(
		const KeymasterKeyBlob& blob,
		const AuthorizationSet& additional_params,
		KeymasterKeyBlob* key_material,
		AuthorizationSet* hw_enforced,
		AuthorizationSet* sw_enforced) {

	AuthorizationSet hidden;
	keymaster_error_t error = AmlBuildHiddenAuthorizations(additional_params, &hidden);
	if (error != KM_ERROR_OK)
		return error;

	// Assume it's an integrity-assured blob (new software-only blob, or new keymaster0-backed
	// blob).
	error = AmlDeserializeIntegrityAssuredBlob(blob, hidden, key_material, hw_enforced, sw_enforced);
	return error;
//	return ParseKeymaster1HwBlob(blob, additional_params, key_material, hw_enforced,
//			sw_enforced);
}

keymaster_error_t AmlBuildHiddenAuthorizations(
		const AuthorizationSet& input_set,
		AuthorizationSet* hidden) {
	keymaster_blob_t entry;
	if (input_set.GetTagValue(TAG_APPLICATION_ID, &entry))
		hidden->push_back(TAG_APPLICATION_ID, entry.data, entry.data_length);
	if (input_set.GetTagValue(TAG_APPLICATION_DATA, &entry))
		hidden->push_back(TAG_APPLICATION_DATA, entry.data, entry.data_length);
#if 0
	hidden->push_back(TAG_ROOT_OF_TRUST, reinterpret_cast<const uint8_t*>(root_of_trust_.data()),
			root_of_trust_.size());
#endif
	return AmlTranslateAuthorizationSetError(hidden->is_valid());
}

static keymaster_error_t validate_rsa_specific_new_key_params(
                                    const keymaster_key_format_t key_format,
                                    const KeymasterKeyBlob& key_material,
                                    AuthorizationSet* updated_description)
{
    keymaster_error_t error = KM_ERROR_OK;
    UniquePtr<EVP_PKEY, EVP_PKEY_Delete> pkey;
    UniquePtr<RSA, RSA_Delete> rsa_key;
    uint64_t public_exponent_from_key = 0;
    uint64_t public_exponent_from_tag = 0;
    uint32_t key_size_from_key = 0;
    uint32_t key_size_from_tag = 0;

    error = KeyMaterialToEvpKey(key_format, key_material, KM_ALGORITHM_RSA, &pkey);
    if (error != KM_ERROR_OK)
        return error;

    rsa_key.reset(EVP_PKEY_get1_RSA(pkey.get()));
    if (!rsa_key.get())
        return TranslateLastOpenSslError();

    public_exponent_from_key = BN_get_word(rsa_key->e);
    if (public_exponent_from_key == 0xffffffffL)
        return KM_ERROR_INVALID_KEY_BLOB;
    if (!updated_description->GetTagValue(TAG_RSA_PUBLIC_EXPONENT, &public_exponent_from_tag))
        updated_description->push_back(TAG_RSA_PUBLIC_EXPONENT, public_exponent_from_key);
    else {
        if (public_exponent_from_tag != public_exponent_from_key) {
            LOG_E("Imported public exponent (%u) does not match specified public exponent (%u)",
                    public_exponent_from_tag, public_exponent_from_key);
            return KM_ERROR_IMPORT_PARAMETER_MISMATCH;
        }
    }
    key_size_from_key = RSA_size(rsa_key.get()) * 8;
    if (!updated_description->GetTagValue(TAG_KEY_SIZE, &key_size_from_tag))
        updated_description->push_back(TAG_KEY_SIZE, key_size_from_key);
    else {
        if (key_size_from_key != key_size_from_tag) {
            LOG_E("Imported key size (%u bits) does not match specified key size (%u bits)",
                    key_size_from_key, key_size_from_tag);
            return KM_ERROR_IMPORT_PARAMETER_MISMATCH;
        }
    }
    return KM_ERROR_OK;
}

static keymaster_error_t validate_ec_specific_new_key_params(
                                    const keymaster_key_format_t key_format,
                                    const KeymasterKeyBlob& key_material,
                                    AuthorizationSet* updated_description)
{
    keymaster_error_t error = KM_ERROR_OK;
    UniquePtr<EVP_PKEY, EVP_PKEY_Delete> pkey;
    UniquePtr<EC_KEY, EC_Delete> ec_key;
    uint32_t key_size_bits_from_tag = 0;
    size_t key_size_bits_from_key = 0;

    error = KeyMaterialToEvpKey(key_format, key_material, KM_ALGORITHM_EC, &pkey);
    if (error != KM_ERROR_OK)
        return error;

    ec_key.reset(EVP_PKEY_get1_EC_KEY(pkey.get()));
    if (!ec_key.get())
        return TranslateLastOpenSslError();

    error = EcKeyFactory::get_group_size(*EC_KEY_get0_group(ec_key.get()), &key_size_bits_from_key);
    if (error != KM_ERROR_OK)
        return error;

    if (!updated_description->GetTagValue(TAG_KEY_SIZE, &key_size_bits_from_tag)) {
        updated_description->push_back(TAG_KEY_SIZE, key_size_bits_from_key);
    }
    else {
        if (key_size_bits_from_tag != key_size_bits_from_key)
            return KM_ERROR_IMPORT_PARAMETER_MISMATCH;
    }
    return KM_ERROR_OK;
}

static keymaster_error_t validate_aes_specific_new_key_params(
                    const keymaster_key_format_t input_key_material_format,
                    const KeymasterKeyBlob& input_key_material,
                    AuthorizationSet& authorizations)
{
    uint32_t key_size_bits;
    if (!authorizations.GetTagValue(TAG_KEY_SIZE, &key_size_bits)) {
        // Default key size if not specified.
        key_size_bits = input_key_material.key_material_size * 8;
        authorizations.push_back(TAG_KEY_SIZE, key_size_bits);
    }

    if (authorizations.Contains(TAG_BLOCK_MODE, KM_MODE_GCM)) {
        uint32_t min_tag_length;
        if (!authorizations.GetTagValue(TAG_MIN_MAC_LENGTH, &min_tag_length))
            return KM_ERROR_MISSING_MIN_MAC_LENGTH;

        if (min_tag_length % 8 != 0)
            return KM_ERROR_UNSUPPORTED_MIN_MAC_LENGTH;

        if (min_tag_length < kMinGcmTagLength || min_tag_length > kMaxGcmTagLength)
            return KM_ERROR_UNSUPPORTED_MIN_MAC_LENGTH;
    } else {
        // Not GCM
        if (authorizations.find(TAG_MIN_MAC_LENGTH) != -1) {
            LOG_E("KM_TAG_MIN_MAC_LENGTH found for non AES-GCM key", 0);
            return KM_ERROR_INVALID_TAG;
        }
    }

    if (!(key_size_bits == 128 || key_size_bits == 192 || key_size_bits == 256))
        return KM_ERROR_UNSUPPORTED_KEY_SIZE;

    if (input_key_material_format != KM_KEY_FORMAT_RAW)
        return KM_ERROR_UNSUPPORTED_KEY_FORMAT;

    if (key_size_bits != input_key_material.key_material_size * 8) {
        LOG_E("Expected %u-bit key data but got %u bits",
                key_size_bits, input_key_material.key_material_size * 8);
        return KM_ERROR_INVALID_KEY_BLOB;
    }
    return KM_ERROR_OK;
}

static keymaster_error_t validate_hmac_specific_new_key_params(
                    const keymaster_key_format_t input_key_material_format,
                    const KeymasterKeyBlob& input_key_material,
                    AuthorizationSet& authorizations,
                    uint32_t* optee_obj_type)
{
    uint32_t key_size_bits;

    if (!authorizations.GetTagValue(TAG_KEY_SIZE, &key_size_bits)) {
        // Default key size if not specified.
        key_size_bits = input_key_material.key_material_size * 8;
        authorizations.push_back(TAG_KEY_SIZE, key_size_bits);
    }

    uint32_t min_mac_length_bits;
    if (!authorizations.GetTagValue(TAG_MIN_MAC_LENGTH, &min_mac_length_bits))
        return KM_ERROR_MISSING_MIN_MAC_LENGTH;

    keymaster_digest_t digest;
    if (!authorizations.GetTagValue(TAG_DIGEST, &digest)) {
        return KM_ERROR_UNSUPPORTED_DIGEST;
    }

    size_t hash_size_bits = 0;
    switch (digest) {
    case KM_DIGEST_NONE:
        return KM_ERROR_UNSUPPORTED_DIGEST;
    case KM_DIGEST_MD5:
        hash_size_bits = 128;
        *optee_obj_type = TEE_TYPE_HMAC_MD5;
        break;
    case KM_DIGEST_SHA1:
        hash_size_bits = 160;
        *optee_obj_type = TEE_TYPE_HMAC_SHA1;
        break;
    case KM_DIGEST_SHA_2_224:
        hash_size_bits = 224;
        *optee_obj_type = TEE_TYPE_HMAC_SHA224;
        break;
    case KM_DIGEST_SHA_2_256:
        hash_size_bits = 256;
        *optee_obj_type = TEE_TYPE_HMAC_SHA256;
        break;
    case KM_DIGEST_SHA_2_384:
        hash_size_bits = 384;
        *optee_obj_type = TEE_TYPE_HMAC_SHA384;
        break;
    case KM_DIGEST_SHA_2_512:
        hash_size_bits = 512;
        *optee_obj_type = TEE_TYPE_HMAC_SHA512;
        break;
    };

    if (hash_size_bits == 0) {
        // digest was not matched
        return KM_ERROR_UNSUPPORTED_DIGEST;
    }

    if (min_mac_length_bits % 8 != 0 || min_mac_length_bits > hash_size_bits)
        return KM_ERROR_UNSUPPORTED_MIN_MAC_LENGTH;

    if (min_mac_length_bits < kMinHmacLengthBits)
        return KM_ERROR_UNSUPPORTED_MIN_MAC_LENGTH;

    if (!(key_size_bits > 0 && key_size_bits % 8 == 00 && key_size_bits <= 2048))
        return KM_ERROR_UNSUPPORTED_KEY_SIZE;

    if (input_key_material_format != KM_KEY_FORMAT_RAW)
        return KM_ERROR_UNSUPPORTED_KEY_FORMAT;

    if (key_size_bits != input_key_material.key_material_size * 8) {
        LOG_E("Expected %u-bit key data but got %u bits",
                key_size_bits, input_key_material.key_material_size * 8);
        return KM_ERROR_INVALID_KEY_BLOB;
    }
    return KM_ERROR_OK;
}

keymaster_error_t update_import_key_description(const AuthorizationSet& key_description,
                                                const keymaster_algorithm_t algorithm,
                                                const keymaster_key_format_t key_format,
                                                const KeymasterKeyBlob& key_material,
                                                AuthorizationSet* updated_description,
                                                uint32_t* optee_obj_type)
{
    keymaster_error_t error = KM_ERROR_OK;
    if (!updated_description || !optee_obj_type)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    updated_description->Reinitialize(key_description);

    if (algorithm == KM_ALGORITHM_RSA) {
        error = validate_rsa_specific_new_key_params(key_format, key_material, updated_description);
        if (error != KM_ERROR_OK) {
            LOG_E("validate_rsa_specific_new_key_params failed", 0);
            return error;
        }
        *optee_obj_type = TEE_TYPE_RSA_KEYPAIR;
    }
    else if (algorithm == KM_ALGORITHM_EC) {
        error = validate_ec_specific_new_key_params(key_format, key_material, updated_description);
        if (error != KM_ERROR_OK) {
            LOG_E("validate_ec_specific_new_key_params failed", 0);
            return error;
        }
        *optee_obj_type = TEE_TYPE_ECDSA_KEYPAIR;
    }
    else if (algorithm == KM_ALGORITHM_AES) {
        error = validate_aes_specific_new_key_params(key_format, key_material, *updated_description);
        if (error != KM_ERROR_OK) {
            LOG_E("validate_ec_specific_new_key_params failed", 0);
            return error;
        }
        *optee_obj_type = TEE_TYPE_AES;
    }
    else if (algorithm == KM_ALGORITHM_HMAC) {
        error = validate_hmac_specific_new_key_params(key_format, key_material,
                *updated_description, optee_obj_type);
        if (error != KM_ERROR_OK) {
            LOG_E("validate_ec_specific_new_key_params failed", 0);
            return error;
        }
    }
    else {
        return KM_ERROR_UNSUPPORTED_ALGORITHM;
    }
    return KM_ERROR_OK;
}

