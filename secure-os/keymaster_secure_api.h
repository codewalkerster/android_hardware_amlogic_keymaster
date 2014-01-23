#ifndef __KEYMASTER_SECURE_API_H__
#define __KEYMASTER_SECURE_API_H__

#ifdef __cplusplus
extern "C" {
#endif
    /*	The API initializes the crypto hardware.
        Parameters:		none
        Returns:			OEMCrypto_SUCCESS success
        OEMCrypto_FAILURE failed to initialize crypto hardware
     */
    int KM_Secure_Initialize(void);
    int KM_Secure_Terminate(void);
    int KM_secure_generate_keypair(const keymaster_device_t* dev,
                               const keymaster_keypair_t key_type,
                               const void* key_params,
							   uint8_t** key_blob, size_t* key_blob_length);
    int KM_secure_get_keypair_public(const struct keymaster_device* dev,
			                 const uint8_t* key_blob,
                             const size_t key_blob_length,
							 uint8_t** x509_data, size_t* x509_data_length);
    int KM_secure_import_keypair(const struct keymaster_device* dev,
			                 const uint8_t* key,
                             const size_t key_length,
							 uint8_t** key_blob, size_t* key_blob_length);

    int KM_secure_get_key_type(const uint8_t* key_blob);

    int KM_secure_sign_data( const struct keymaster_device* dev,
		                 const keymaster_keypair_t key_type,
		                 const void* params, 
						 const uint8_t* key_blob, const size_t key_blob_length,
						 const uint8_t* data, const size_t data_length,
						 uint8_t** signed_data, size_t* signed_data_length);

    int KM_secure_verify_data( const struct keymaster_device* dev,
		                 const keymaster_keypair_t key_type,
		                 const void* params, 
						 const uint8_t* key_blob, const size_t key_blob_length,
						 const uint8_t* signed_data, const size_t signed_data_length,
						 const uint8_t* signature, const size_t signature_length);

    int KM_secure_delete_keypair(const struct keymaster_device* dev,
		                     const uint8_t* key_blob, 
							 const size_t key_blob_length);

#ifdef __cplusplus
}
#endif

#endif
