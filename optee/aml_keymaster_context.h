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

#ifndef _AML_KEYMASTER_CONTEXT_H_
#define _AML_KEYMASTER_CONTEXT_H_

#include <iostream>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/evp.h>


#include <hardware/keymaster_defs.h>
#include <keymaster1_secure_api.h>

#include <keymaster/android_keymaster_utils.h>
#include <keymaster/authorization_set.h>
#include <auth_encrypted_key_blob.h>
#include <ocb_utils.h>
#include <openssl_utils.h>
#include <keymaster/ec_key_factory.h>
#include <rsa_key.h>
#include <openssl_err.h>
#include <aes_key.h>
#include <hmac_key.h>
#include "aml_integrity_assured_key_blob.h"

using namespace keymaster;
keymaster_error_t AmlCreateKeyBlob(const AuthorizationSet& auths, keymaster_key_origin_t origin,
		const KeymasterKeyBlob& key_material, KeymasterKeyBlob* blob,
		AuthorizationSet* hw_enforced,
		AuthorizationSet* sw_enforced);

keymaster_error_t AmlParseKeyBlob(const KeymasterKeyBlob& blob,
		const AuthorizationSet& additional_params,
		KeymasterKeyBlob* key_material, AuthorizationSet* hw_enforced,
		AuthorizationSet* sw_enforced, bool verify);

keymaster_error_t ParseOldSoftkeymasterBlob(const KeymasterKeyBlob& blob,
		KeymasterKeyBlob* key_material,
		AuthorizationSet* hw_enforced,
		AuthorizationSet* sw_enforced);
keymaster_error_t ParseKeymaster1HwBlob(const KeymasterKeyBlob& blob,
		const AuthorizationSet& additional_params,
		KeymasterKeyBlob* key_material,
		AuthorizationSet* hw_enforced,
		AuthorizationSet* sw_enforced);
keymaster_error_t FakeKeyAuthorizations(EVP_PKEY* pubkey, AuthorizationSet* hw_enforced,
		AuthorizationSet* sw_enforced);
keymaster_error_t AmlBuildHiddenAuthorizations(const AuthorizationSet& input_set,
		AuthorizationSet* hidden);
keymaster_error_t update_import_key_description(const AuthorizationSet& key_description,
                                                const keymaster_algorithm_t algorithm,
                                                const keymaster_key_format_t key_format,
                                                const KeymasterKeyBlob& key_material,
                                                AuthorizationSet* updated_description,
                                                uint32_t* optee_obj_type);

#endif
