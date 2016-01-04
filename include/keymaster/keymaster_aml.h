/*
 * Copyright 2013 The Android Open Source Project
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

#include <hardware/keymaster0.h>
#include <hardware/keymaster1.h>

#ifndef KEYMASTER_AML_H
#define KEYMASTER_AML_H

extern "C" {
extern struct keystore_module aml_keymaster_device_module;
}
int aml_terminate(void);

/* keymaster1 APis */
keymaster_error_t aml_get_supported_algorithms(const struct keymaster1_device* dev,
	keymaster_algorithm_t** algorithms,
	size_t* algorithms_length);

keymaster_error_t aml_get_supported_block_modes(const struct keymaster1_device* dev,
	keymaster_algorithm_t algorithm,
	keymaster_purpose_t purpose,
	keymaster_block_mode_t** modes,
	size_t* modes_length);

keymaster_error_t aml_get_supported_padding_modes(const struct keymaster1_device* dev,
	keymaster_algorithm_t algorithm,
	keymaster_purpose_t purpose,
	keymaster_padding_t** modes,
	size_t* modes_length);

keymaster_error_t aml_get_supported_digests(const struct keymaster1_device* dev,
	keymaster_algorithm_t algorithm,
	keymaster_purpose_t purpose,
	keymaster_digest_t** digests,
	size_t* digests_length);

keymaster_error_t aml_get_supported_import_formats(const struct keymaster1_device* dev,
	keymaster_algorithm_t algorithm,
	keymaster_key_format_t** formats,
	size_t* formats_length);

keymaster_error_t aml_get_supported_export_formats(const struct keymaster1_device* dev,
	keymaster_algorithm_t algorithm,
	keymaster_key_format_t** formats,
	size_t* formats_length);

keymaster_error_t aml_add_rng_entropy(const struct keymaster1_device* dev, const uint8_t* data,
	size_t data_length);

keymaster_error_t aml_generate_key(const struct keymaster1_device* dev,
	const keymaster_key_param_set_t* params,
	keymaster_key_blob_t* key_blob,
	keymaster_key_characteristics_t** characteristics);

keymaster_error_t aml_get_key_characteristics(const struct keymaster1_device* dev,
	const keymaster_key_blob_t* key_blob,
	const keymaster_blob_t* client_id,
	const keymaster_blob_t* app_data,
	keymaster_key_characteristics_t** characteristics);

keymaster_error_t aml_import_key(const struct keymaster1_device* dev,
	const keymaster_key_param_set_t* params,
	keymaster_key_format_t key_format,
	const keymaster_blob_t* key_data,
	keymaster_key_blob_t* key_blob,
	keymaster_key_characteristics_t** characteristics);

keymaster_error_t aml_export_key(const struct keymaster1_device* dev,
	keymaster_key_format_t export_format,
	const keymaster_key_blob_t* key_to_export,
	const keymaster_blob_t* client_id,
	const keymaster_blob_t* app_data,
	keymaster_blob_t* export_data);

keymaster_error_t aml_delete_key(const struct keymaster1_device* dev,
	const keymaster_key_blob_t* key);

keymaster_error_t aml_delete_all_keys(const struct keymaster1_device* dev);

keymaster_error_t aml_begin(const struct keymaster1_device* dev, keymaster_purpose_t purpose,
	const keymaster_key_blob_t* key,
	const keymaster_key_param_set_t* in_params,
	keymaster_key_param_set_t* out_params,
	keymaster_operation_handle_t* operation_handle);

keymaster_error_t aml_update(const struct keymaster1_device* dev,
	keymaster_operation_handle_t operation_handle,
	const keymaster_key_param_set_t* in_params,
	const keymaster_blob_t* input, size_t* input_consumed,
	keymaster_key_param_set_t* out_params, keymaster_blob_t* output);

keymaster_error_t aml_finish(const struct keymaster1_device* dev,
	keymaster_operation_handle_t operation_handle,
	const keymaster_key_param_set_t* in_params,
	const keymaster_blob_t* signature,
	keymaster_key_param_set_t* out_params, keymaster_blob_t* output);

keymaster_error_t aml_abort(const struct keymaster1_device* dev,
	keymaster_operation_handle_t operation_handle);

#endif /* KEYMASTER_AML_H */
