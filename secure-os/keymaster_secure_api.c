#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>

//#include "keymaster_secure_api.h"
#include <hardware/keymaster.h>
#include "otz_id.h"
#include "otz_tee_client_api.h"

#define LENGTH_SHAREMEM  (256)

#ifdef ANDROID_BUILD
#include <android/log.h>
#define LOG_TAG "OTZTEE"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG,  __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG,  __VA_ARGS__)
#define SECURE_PRINTF LOGD
#else
#include <sys/syscall.h>
#define gettid() syscall(__NR_gettid)
#define SECURE_PRINTF printf
#endif

TEEC_Context KM_context;
TEEC_Session KM_session;
static int KM_inited = 0;


/*	The API initializes the crypto hardware.
    Parameters:		none
    Returns: 0  -> success
	         -1 -> failed 
 */
int KM_Secure_Initialize(void)
{
    TEEC_Result result;
    TEEC_UUID svc_id = OTZ_SVC_KEYMASTER;
	TEEC_Operation operation;

    SECURE_PRINTF("[opentz] %s\n",__func__);
	
	if (KM_inited){
      SECURE_PRINTF("KM_session has been inited. Skip it!\n");
	  return 0;
	}

	result = TEEC_InitializeContext(
            NULL,
            &KM_context);

    if(result != TEEC_SUCCESS) {
        SECURE_PRINTF("TEEC_InitializeContext OEMCrypto_ERROR_INIT_FAILED\n");
        return -1;
    }

    result = TEEC_OpenSession(
            &KM_context,
            &KM_session,
            &svc_id,
            TEEC_LOGIN_PUBLIC,
            NULL,
            NULL,
            NULL);

    if(result != TEEC_SUCCESS) {
        SECURE_PRINTF("TEEC_OpenSession OEMCrypto_ERROR_INIT_FAILED\n");
        TEEC_FinalizeContext(&KM_context);
        return -1;
    }

	operation.paramTypes = TEEC_PARAM_TYPES(
			TEEC_NONE,
			TEEC_NONE,
			TEEC_NONE,
			TEEC_NONE);
	operation.started = 1;

	SECURE_PRINTF("Invoke command OTZ_KEYMASTER_CMD_ID_INIT\n");
	result = TEEC_InvokeCommand(
			&KM_session,
			OTZ_KEYMASTER_CMD_ID_INIT,
			&operation,
			NULL);

	KM_inited = 1;
    return 0;
}


/*	The API closes the operation and releases all resources used
    Parameters: none
    Returns: 0  -> success
	         -1 -> failed 
 */
int KM_Secure_Terminate(void)
{
    SECURE_PRINTF("[opentz] %s\n",__func__);
	TEEC_Operation operation;
    TEEC_Result result;

	operation.paramTypes = TEEC_PARAM_TYPES(
			TEEC_NONE,
			TEEC_NONE,
			TEEC_NONE,
			TEEC_NONE);
	operation.started = 1;

	SECURE_PRINTF("Invoke command OTZ_KEYMASTER_CMD_ID_TERM\n");
	result = TEEC_InvokeCommand(
			&KM_session,
			OTZ_KEYMASTER_CMD_ID_TERM,
			&operation,
			NULL);

    TEEC_CloseSession(&KM_session);
    TEEC_FinalizeContext(&KM_context);

    KM_inited = 0;
    return 0;
}

/*	The API generate a keypair and return a key_blob for further access. 
    Input:  dev - pointer to keymaster_device_t
	        key_type - key type of keypair which will be generated. (EC, DSA, RSA)
			key_params - metadata of keypair
    Output: keyblob - pointer to a pointer of key_blob(key handle)
            key_blob_length - length of returned key_blob
    Returns: 0 - success
	         -1 - failed
*/

int KM_secure_generate_keypair(const keymaster_device_t* dev,
                               const keymaster_keypair_t key_type,
                               const void* key_params,
							   uint8_t** key_blob, size_t* key_blob_length)
{
	TEEC_Operation operation;
	TEEC_Result TEECResult;
	TEEC_SharedMemory sharedMem;
    unsigned int key_params_size = 0;
	int result = -1;
	unsigned int modulus_size = 0;
	unsigned long long public_exponent = 0;

	SECURE_PRINTF("[opentz] %s\n",__func__);

	if(0 == KM_inited) {
		if (KM_Secure_Initialize() < 0){
			SECURE_PRINTF("KM_Secure_Initialize failed ...\n");
			return result;
		}
	}

	if (TYPE_RSA == key_type){
		key_params_size = sizeof(keymaster_rsa_keygen_params_t);
	}
	else if (TYPE_DSA == key_type){
		key_params_size = sizeof(keymaster_dsa_keygen_params_t);
	}
	else if (TYPE_EC == key_type){
		key_params_size = sizeof(keymaster_ec_keygen_params_t);
	}
	else {
		SECURE_PRINTF("unsupport key type\n");
		return result;
	}

	sharedMem.size = LENGTH_SHAREMEM;
	sharedMem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

	TEECResult = TEEC_AllocateSharedMemory(
			&KM_context,
			&sharedMem);
	if(TEECResult != TEEC_SUCCESS) {
		SECURE_PRINTF("Fail to allocate shared memory\n");
	    return result;	
	}

	operation.paramTypes = TEEC_PARAM_TYPES(
			TEEC_VALUE_INPUT,
			TEEC_MEMREF_PARTIAL_INPUT,
			TEEC_VALUE_OUTPUT,
			TEEC_VALUE_OUTPUT
			);

	memset(sharedMem.buffer, 0, sharedMem.size);
	SECURE_PRINTF("sharedMem.size = %d\n", sharedMem.size);

	if (key_params_size <= LENGTH_SHAREMEM){
		memcpy(sharedMem.buffer, key_params, key_params_size);
	}
	else{
		SECURE_PRINTF("key params exceeds the sharedMem size!!\n");
		goto cleanup_2;
	}

	// Input: Key type 
	operation.started = 1;
	operation.params[0].value.a = key_type;
	operation.params[0].value.b = TEEC_VALUE_UNDEF;

	// Input: Key params 
	operation.params[1].memref.parent = &sharedMem;
	operation.params[1].memref.offset = 0;
	operation.params[1].memref.size =  LENGTH_SHAREMEM;
	
	// Output: Key Blob Handle 
	operation.params[2].value.a = TEEC_VALUE_UNDEF;
	operation.params[2].value.b = TEEC_VALUE_UNDEF;

	// Output: Key Blob Length 
	operation.params[3].value.a = TEEC_VALUE_UNDEF;
	operation.params[3].value.b = TEEC_VALUE_UNDEF;

	SECURE_PRINTF("Invoke command OTZ_KM_CMD_ID_GENERATE_KEYPAIR\n");
	TEECResult = TEEC_InvokeCommand(
			&KM_session,
			OTZ_KEYMASTER_CMD_ID_GENERATE_KEYPAIR,
			&operation,
			NULL);

	if (TEECResult != TEEC_SUCCESS){
		SECURE_PRINTF("TEEC_InvokeCommand ERROR!\n");
		goto cleanup_2;
	}

	if(operation.params[3].value.a > 0)
	{
		*key_blob = (unsigned char*)operation.params[2].value.a;
		*key_blob_length = sizeof(unsigned char*);

		result = 0;
	}
	SECURE_PRINTF("result is %d\n", result);

cleanup_2:
	TEEC_ReleaseSharedMemory(&sharedMem);
	return result;
}

/*	The API retrives the key type of a specified key blob(key_handle)  
    Input:  key_blob - pointer to key_blob which has been generated previously. 
    Output: None 
    Returns: key type - success
	         -1 - failed
*/
int KM_secure_get_key_type(const uint8_t* key_blob){
	TEEC_Operation operation;
	TEEC_Result TEECResult;

	SECURE_PRINTF("[opentz] %s\n",__func__);

	if(0 == KM_inited) {
		if (KM_Secure_Initialize() < 0){
			SECURE_PRINTF("KM_Secure_Initialize failed ...\n");
			return -1;
		}
	}

	operation.paramTypes = TEEC_PARAM_TYPES(
			TEEC_VALUE_INPUT,
			TEEC_VALUE_OUTPUT,
			TEEC_NONE,
			TEEC_NONE
			);

	// Input: key blob  
	operation.started = 1;
	operation.params[0].value.a = (uint32_t)key_blob;
	operation.params[0].value.b = TEEC_VALUE_UNDEF;

	// Output: key type 
	operation.params[1].value.a = TEEC_VALUE_UNDEF;
	operation.params[1].value.b = TEEC_VALUE_UNDEF;

	SECURE_PRINTF("Invoke command OTZ_KEYMASTER_CMD_ID_GET_KEY_TYPE\n");
	TEECResult = TEEC_InvokeCommand(
			&KM_session,
			OTZ_KEYMASTER_CMD_ID_GET_KEY_TYPE,
			&operation,
			NULL);

	if (TEECResult != TEEC_SUCCESS){
		SECURE_PRINTF("TEEC_InvokeCommand ERROR!\n");
		return -1;
	}

	SECURE_PRINTF("%s: key type is %x.\n", __func__, operation.params[1].value.a);

	return operation.params[1].value.a;
}

/*	The API verify the signed data with a specified signature
    Input:  dev - pointer to keymaster_device_t
	        key_type - key type of the keypair. (EC, DSA, RSA)
			params - metadata of keypair
            keyblob - pointer to a pointer of key_blob(key handle)
            key_blob_length - length of the  key_blob
			signed_data - pointer to the signed data
			signed_data_length - length of the signed data
			signature - pointer to signature
			signatrue_length - length of signature
    Output: None
    Returns: 0 - success(Matched)
	         -1 - failed
*/

int KM_secure_verify_data( const struct keymaster_device* dev,
		                 const keymaster_keypair_t key_type,
		                 const void* params, 
						 const uint8_t* key_blob, const size_t key_blob_length,
						 const uint8_t* signed_data, const size_t signed_data_length,
						 const uint8_t* signature, const size_t signature_length)
{
	TEEC_Operation operation;
	TEEC_Result TEECResult;
	TEEC_SharedMemory sharedMem;
    size_t key_params_size = 0;
	int result = -1;

	SECURE_PRINTF("[opentz]%s\n",__func__);

	if(0 == KM_inited) {
		if (KM_Secure_Initialize() < 0){
			SECURE_PRINTF("KM_Secure_Initialize failed ...\n");
			return result;
		}
	}

	if (TYPE_RSA == key_type){
		key_params_size = sizeof(keymaster_rsa_sign_params_t);
	}
	else if (TYPE_DSA == key_type){
		key_params_size = sizeof(keymaster_dsa_sign_params_t);
	}
	else if (TYPE_EC == key_type){
		key_params_size = sizeof(keymaster_ec_sign_params_t);
	}
	else {
		SECURE_PRINTF("unsupport key type\n");
		return result;
	}

	sharedMem.size = LENGTH_SHAREMEM * 9; //(256*9) 
	sharedMem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

	TEECResult = TEEC_AllocateSharedMemory(
			&KM_context,
			&sharedMem);
	if(TEECResult != TEEC_SUCCESS) {
		SECURE_PRINTF("Fail to allocate shared memory\n");
	    return result;	
	}

	operation.paramTypes = TEEC_PARAM_TYPES(
			TEEC_VALUE_INOUT,
			TEEC_MEMREF_PARTIAL_INPUT,
			TEEC_MEMREF_PARTIAL_INPUT,
			TEEC_MEMREF_PARTIAL_INPUT
			);

	memset(sharedMem.buffer, 0, sharedMem.size);
	SECURE_PRINTF("sharedMem.size = %d\n", sharedMem.size);

	// Copy params
	if (key_params_size <= LENGTH_SHAREMEM){
		memcpy(sharedMem.buffer, params, key_params_size);
	}
	else{
		SECURE_PRINTF("%s: key_params_size = %d exceeds the sharedMem size = %d!!\n",__func__, key_params_size, LENGTH_SHAREMEM);
		goto cleanup_2;
	}
	// Copy signed data
	SECURE_PRINTF("%s: signed_data length = %d, sharedMem size = %d\n",__func__, signed_data_length, LENGTH_SHAREMEM*4);
	if (signed_data_length <= LENGTH_SHAREMEM * 4){
		memcpy((unsigned char*)((unsigned char*)sharedMem.buffer + LENGTH_SHAREMEM), (unsigned char*)signed_data, signed_data_length);
	}
	else{
	    SECURE_PRINTF("%s: signed_data length = %d, sharedMem size = %d\n",__func__, signed_data_length, LENGTH_SHAREMEM*4);
		goto cleanup_2;
	}
	// Copy signature 
	SECURE_PRINTF("%s: signature length = %d, sharedMem size = %d\n",__func__, signature_length, LENGTH_SHAREMEM*4);
	if (signature_length <= LENGTH_SHAREMEM * 4){
		memcpy((unsigned char*)((unsigned char*)sharedMem.buffer + LENGTH_SHAREMEM*5 ), (unsigned char*)signature, signature_length);
	}
	else{
	    SECURE_PRINTF("%s: signature length = %d, sharedMem size = %d\n",__func__, signature_length, LENGTH_SHAREMEM*4);
		goto cleanup_2;
	}

	// InOut: key blob & returned value 
	operation.started = 1;
	operation.params[0].value.a = (uint32_t)key_blob;
	operation.params[0].value.b = TEEC_VALUE_UNDEF;

	// Input: signed param 
	operation.params[1].memref.parent = &sharedMem;
	operation.params[1].memref.offset = 0;
	operation.params[1].memref.size =  LENGTH_SHAREMEM; //(256) 

	// Input: signed data 
	operation.params[2].memref.parent = &sharedMem;
	operation.params[2].memref.offset = LENGTH_SHAREMEM;
	operation.params[2].memref.size = signed_data_length; //(256*4) Up to 1k bytes

	// Output: signature 
	operation.params[3].memref.parent = &sharedMem;
	operation.params[3].memref.offset = LENGTH_SHAREMEM * 5;
	operation.params[3].memref.size =  signature_length; //(256*4) Up to 1k bytes

	SECURE_PRINTF("Invoke command OTZ_KEYMASTER_CMD_ID_VERIFY_DATA\n");
	TEECResult = TEEC_InvokeCommand(
			&KM_session,
			OTZ_KEYMASTER_CMD_ID_VERIFY_DATA,
			&operation,
			NULL);

	if (TEECResult != TEEC_SUCCESS){
		SECURE_PRINTF("TEEC_InvokeCommand ERROR!\n");
		goto cleanup_2;
	}

	if(operation.params[0].value.a == 0){
		SECURE_PRINTF("Verify successfully!\n");
		result = 0;
	}
	else
		SECURE_PRINTF("Verify failed!\n");

cleanup_2:
	SECURE_PRINTF("result is %d\n", result);
	TEEC_ReleaseSharedMemory(&sharedMem);
	return result;
}

/*	The API sign the data with a specified key 
    Input:  dev - pointer to keymaster_device_t
	        key_type - key type of the keypair. (EC, DSA, RSA)
			params - metadata of keypair
            keyblob - pointer to a key_blob(key handle)
            key_blob_length - length of the key_blob
			data - pointer to data which will be signed
			data_length - length of the data
    Output: signed_data - pointer to a pointer to the hold signed data
	        signed_data_length - pointer to the length of signed data 
    Returns: 0 - success
	         -1 - failed
*/
int KM_secure_sign_data( const struct keymaster_device* dev,
		                 const keymaster_keypair_t key_type,
		                 const void* params, 
						 const uint8_t* key_blob, const size_t key_blob_length,
						 const uint8_t* data, const size_t data_length,
						 uint8_t** signed_data, size_t* signed_data_length)
{
	TEEC_Operation operation;
	TEEC_Result TEECResult;
	TEEC_SharedMemory sharedMem;
    size_t key_params_size = 0;
	int result = -1;

	SECURE_PRINTF("[opentz]%s\n",__func__);

	if(0 == KM_inited) {
		if (KM_Secure_Initialize() < 0){
			SECURE_PRINTF("KM_Secure_Initialize failed ...\n");
			return result;
		}
	}

	if (TYPE_RSA == key_type){
		key_params_size = sizeof(keymaster_rsa_sign_params_t);
	}
	else if (TYPE_DSA == key_type){
		key_params_size = sizeof(keymaster_dsa_sign_params_t);
	}
	else if (TYPE_EC == key_type){
		key_params_size = sizeof(keymaster_ec_sign_params_t);
	}
	else {
		SECURE_PRINTF("unsupport key type\n");
		return result;
	}

	sharedMem.size = LENGTH_SHAREMEM * 9; //(256*4) Up to 1k bytes
	sharedMem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

	TEECResult = TEEC_AllocateSharedMemory(
			&KM_context,
			&sharedMem);
	if(TEECResult != TEEC_SUCCESS) {
		SECURE_PRINTF("Fail to allocate shared memory\n");
	    return result;	
	}

	operation.paramTypes = TEEC_PARAM_TYPES(
			TEEC_VALUE_INPUT,
			TEEC_MEMREF_PARTIAL_INPUT,
			TEEC_MEMREF_PARTIAL_INPUT,
			TEEC_MEMREF_PARTIAL_OUTPUT
			);

	memset(sharedMem.buffer, 0, sharedMem.size);
	SECURE_PRINTF("sharedMem.size = %d\n", sharedMem.size);

	// Copy params
	if (key_params_size <= LENGTH_SHAREMEM){
		memcpy(sharedMem.buffer, params, key_params_size);
	}
	else{
		SECURE_PRINTF("%s: key_params_size = %d exceeds the sharedMem size = %d!!\n",__func__, key_params_size, LENGTH_SHAREMEM);
		goto cleanup_2;
	}
	// Copy data
	SECURE_PRINTF("%s: data length = %d, sharedMem size = %d\n",__func__, data_length, LENGTH_SHAREMEM*4);
	if (data_length <= LENGTH_SHAREMEM * 4){
		memcpy((unsigned char*)((unsigned char*)sharedMem.buffer + LENGTH_SHAREMEM), data, data_length);
	}
	else{
		SECURE_PRINTF("%s: data length = %d exceeds the sharedMem size = %d!!\n",__func__, data_length, LENGTH_SHAREMEM*4);
		goto cleanup_2;
	}

	// Input: key blob  
	operation.started = 1;
	operation.params[0].value.a = (uint32_t)key_blob;
	operation.params[0].value.b = TEEC_VALUE_UNDEF;

	// Input: key param 
	operation.params[1].memref.parent = &sharedMem;
	operation.params[1].memref.offset = 0;
	operation.params[1].memref.size =  LENGTH_SHAREMEM; //(256*4) Up to 1k bytes

	// Input: data 
	operation.params[2].memref.parent = &sharedMem;
	operation.params[2].memref.offset = LENGTH_SHAREMEM;
	operation.params[2].memref.size = data_length; //(256*4) Up to 1k bytes

	// Output: signed data 
	operation.params[3].memref.parent = &sharedMem;
	operation.params[3].memref.offset = LENGTH_SHAREMEM * 5;
	operation.params[3].memref.size =  LENGTH_SHAREMEM * 4; //(256*4) Up to 1k bytes

	SECURE_PRINTF("Invoke command OTZ_KEYMASTER_CMD_ID_SIGN_DATA\n");
	TEECResult = TEEC_InvokeCommand(
			&KM_session,
			OTZ_KEYMASTER_CMD_ID_SIGN_DATA,
			&operation,
			NULL);

	if (TEECResult != TEEC_SUCCESS){
		SECURE_PRINTF("TEEC_InvokeCommand ERROR!\n");
		goto cleanup_2;
	}

	if(operation.params[3].memref.size > 0)
	{
		*signed_data_length = operation.params[3].memref.size;

		*signed_data = (uint8_t*)malloc(*signed_data_length);
		if (NULL == *signed_data){
		   SECURE_PRINTF("Failed allocate buffer for x509 data!\n");
		   goto cleanup_2;
		}
		memcpy(*signed_data, (uint8_t*)((uint8_t*)sharedMem.buffer+LENGTH_SHAREMEM*5), operation.params[3].memref.size);

		result = 0;
	}

cleanup_2:
	SECURE_PRINTF("result is %d\n", result);
	TEEC_ReleaseSharedMemory(&sharedMem);
	return result;
}

/*	The API retrives the public key of a specified keypair 
    Input:  dev - pointer to keymaster_device_t
            keyblob - pointer to a key_blob(key handle)
            key_blob_length - length of the key_blob
    Output: x509_data - pointer to a pointer to the public key
	        x509_data_length - pointer to the length of public key 
    Returns: 0 - success
	         -1 - failed
*/
int KM_secure_get_keypair_public(const struct keymaster_device* dev,
		                     const uint8_t* key_blob,
                             const size_t key_blob_length,
							 uint8_t** x509_data, size_t* x509_data_length)
{
	TEEC_Operation operation;
	TEEC_Result TEECResult;
	TEEC_SharedMemory sharedMem;
	int result = -1;

	SECURE_PRINTF("[opentz] %s\n",__func__);

	if(0 == KM_inited) {
		if (KM_Secure_Initialize() < 0){
			SECURE_PRINTF("KM_Secure_Initialize failed ...\n");
			return result;
		}
	}

	sharedMem.size = LENGTH_SHAREMEM * 4; //(256*4) Up to 1k bytes
	sharedMem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

	TEECResult = TEEC_AllocateSharedMemory(
			&KM_context,
			&sharedMem);
	if(TEECResult != TEEC_SUCCESS) {
		SECURE_PRINTF("Fail to allocate shared memory\n");
	    return result;	
	}

	operation.paramTypes = TEEC_PARAM_TYPES(
			TEEC_VALUE_INPUT,
			TEEC_VALUE_INPUT,
			TEEC_MEMREF_PARTIAL_OUTPUT,
			TEEC_NONE
			);

	memset(sharedMem.buffer, 0, sharedMem.size);
	SECURE_PRINTF("sharedMem.size = %d\n", sharedMem.size);

	// Input: key blob  
	operation.started = 1;
	operation.params[0].value.a = (uint32_t)key_blob;
	operation.params[0].value.b = TEEC_VALUE_UNDEF;

	// Input: key blob length 
	operation.params[1].value.a = (uint32_t)key_blob_length;
	operation.params[1].value.b = TEEC_VALUE_UNDEF;

	// Output: x509 public key data and length 
	operation.params[2].memref.parent = &sharedMem;
	operation.params[2].memref.offset = 0;
	operation.params[2].memref.size =  LENGTH_SHAREMEM * 4; //(256*4) Up to 1k bytes

	SECURE_PRINTF("Invoke command OTZ_KEYMASTER_CMD_ID_GET_KEYPAIR_PUBLIC\n");
	TEECResult = TEEC_InvokeCommand(
			&KM_session,
			OTZ_KEYMASTER_CMD_ID_GET_KEYPAIR_PUBLIC,
			&operation,
			NULL);

	if (TEECResult != TEEC_SUCCESS){
		SECURE_PRINTF("TEEC_InvokeCommand ERROR!\n");
		goto cleanup_2;
	}

	if(operation.params[2].memref.size > 0)
	{
		*x509_data_length = operation.params[2].memref.size;

		*x509_data = (uint8_t*)malloc(*x509_data_length);
		if (NULL == *x509_data){
		   SECURE_PRINTF("Failed allocate buffer for x509 data!\n");
		   goto cleanup_2;
		}
		memcpy(*x509_data, (const uint8_t*)sharedMem.buffer, operation.params[2].memref.size);

		result = 0;
	}

cleanup_2:
	SECURE_PRINTF("result is %d\n", result);
	TEEC_ReleaseSharedMemory(&sharedMem);
	return result;
}

/*	The API imports a keypair and get the key blob(key handle) 
    Input:  dev - pointer to keymaster_device_t
            key - pointer to a keypair
            key_length - length of the keypair
    Output: key_blob - pointer to a pointer to the key_blob(key_handle) 
	        key_blob_length - pointer to the length of the key blob 
    Returns: 0 - success
	         -1 - failed
*/
int KM_secure_import_keypair(const struct keymaster_device* dev,
		                     const uint8_t* key,
                             const size_t key_length,
							 uint8_t** key_blob, size_t* key_blob_length)
{
	TEEC_Operation operation;
	TEEC_Result TEECResult;
	TEEC_SharedMemory sharedMem;
	int result = -1;

	SECURE_PRINTF("[opentz] %s\n",__func__);

	if(0 == KM_inited) {
		if (KM_Secure_Initialize() < 0){
			SECURE_PRINTF("KM_Secure_Initialize failed ...\n");
			return result;
		}
	}

	// Initialize shared memory
	sharedMem.size = LENGTH_SHAREMEM * 6;
	sharedMem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

	TEECResult = TEEC_AllocateSharedMemory(
			&KM_context,
			&sharedMem);
	if(TEECResult != TEEC_SUCCESS) {
		SECURE_PRINTF("Fail to allocate shared memory\n");
	    return result;	
	}

	operation.paramTypes = TEEC_PARAM_TYPES(
			TEEC_MEMREF_PARTIAL_INPUT,
			TEEC_VALUE_INPUT,
			TEEC_VALUE_OUTPUT,
			TEEC_VALUE_OUTPUT
			);

	memset(sharedMem.buffer, 0, sharedMem.size);
	SECURE_PRINTF("sharedMem.size = %d\n", sharedMem.size);

	if (key_length <= sharedMem.size){
		memcpy(sharedMem.buffer, key, key_length);
	}
	else{
		SECURE_PRINTF("%s: key size = %d exceeds the sharedMem size = %d!!\n",__func__, key_length, sharedMem.size);
		goto cleanup_2;
	}

	// Input: key data 
	operation.started = 1;
	operation.params[0].memref.parent = &sharedMem;
	operation.params[0].memref.offset = 0;
	operation.params[0].memref.size =  LENGTH_SHAREMEM * 6;

	// Input: key length 
	operation.params[1].value.a = (uint32_t)key_length;
	operation.params[1].value.b = TEEC_VALUE_UNDEF;

	// Output: key blob handle and length 
	operation.params[2].value.a = TEEC_VALUE_UNDEF;
	operation.params[2].value.b = TEEC_VALUE_UNDEF;

	operation.params[3].value.a = TEEC_VALUE_UNDEF;
	operation.params[3].value.b = TEEC_VALUE_UNDEF;

	SECURE_PRINTF("Invoke command OTZ_KEYMASTER_CMD_ID_IMPORT_KEYPAIR\n");
	TEECResult = TEEC_InvokeCommand(
			&KM_session,
			OTZ_KEYMASTER_CMD_ID_IMPORT_KEYPAIR,
			&operation,
			NULL);

	if (TEECResult != TEEC_SUCCESS){
		SECURE_PRINTF("TEEC_InvokeCommand ERROR!\n");
		goto cleanup_2;
	}

	if(operation.params[3].value.a > 0)
	{
		*key_blob = (unsigned char*)operation.params[2].value.a;
		*key_blob_length = sizeof(unsigned char*);

		result = 0;
	}

cleanup_2:
	SECURE_PRINTF("result is %d\n", result);
	TEEC_ReleaseSharedMemory(&sharedMem);
	return result;
}

/*	The API retrives the key type of a specified key blob(key_handle)  
    Input:  key_blob - pointer to key_blob which has been generated previously. 
    Output: None 
    Returns: key type - success
	         -1 - failed
*/
int KM_secure_delete_keypair(const struct keymaster_device* dev,
		                     const uint8_t* key_blob, 
							 const size_t key_blob_length){
	TEEC_Operation operation;
	TEEC_Result TEECResult;

	SECURE_PRINTF("[opentz] %s\n",__func__);

	if(0 == KM_inited) {
		if (KM_Secure_Initialize() < 0){
			SECURE_PRINTF("KM_Secure_Initialize failed ...\n");
			return -1;
		}
	}

	operation.paramTypes = TEEC_PARAM_TYPES(
			TEEC_VALUE_INPUT,
			TEEC_VALUE_OUTPUT,
			TEEC_NONE,
			TEEC_NONE
			);

	// Input: key blob  
	operation.started = 1;
	operation.params[0].value.a = (uint32_t)key_blob;
	operation.params[0].value.b = TEEC_VALUE_UNDEF;

	// Output: status 
	operation.params[1].value.a = TEEC_VALUE_UNDEF;
	operation.params[1].value.b = TEEC_VALUE_UNDEF;

	SECURE_PRINTF("Invoke command OTZ_KEYMASTER_CMD_ID_DELETE_KEYPAIR\n");
	TEECResult = TEEC_InvokeCommand(
			&KM_session,
			OTZ_KEYMASTER_CMD_ID_DELETE_KEYPAIR,
			&operation,
			NULL);

	if (TEECResult != TEEC_SUCCESS){
		SECURE_PRINTF("TEEC_InvokeCommand ERROR!\n");
		return -1;
	}

	SECURE_PRINTF("%s: delete key(%x).\n", __func__, operation.params[1].value.a);

	return (0 == operation.params[1].value.a)? 0: -1;
}

