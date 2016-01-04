#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <util.h>
#include "keymaster_ca.h"

#define SALT_LEN 		(20)

#ifdef ANDROID_BUILD
#define LOG_TAG "OTZTEE"
#include <android/log.h>
//#include <cutils/log.h>
//#define LOGD(...) __android_log_write(ANDROID_LOG_DEBUG, LOG_TAG,  __VA_ARGS__)
//#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG,  __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG,  __VA_ARGS__)
//#define LOG_D printf
#define LOG_D LOGE
#else
#include <sys/syscall.h>
#define gettid() syscall(__NR_gettid)
#define LOG_D printf
#endif

TEEC_Context KM_context;
TEEC_Session KM_session;
static int KM_inited = 0;

struct tee_attr_packed {
	uint32_t attr_id;
	uint32_t a;
	uint32_t b;
};
#if 1
static void dump_buf(const char* name, const uint8_t* buf, const size_t buf_len) {
	uint32_t i = 0;
	LOG_D("\n========== dump %s(%d) start ======== \n", name, buf_len);
	for (i = 0; i < buf_len; i++) {
		if (i % 16 == 0) {
			if (i != 0) LOG_D("\n");
			//LOG_D("\t");
		}
		LOG_D("%.2x ", buf[i]);
	}
	LOG_D("\n========== dump %s end  ============= \n", name);
}
#endif
void add_attr(size_t *attr_count, TEE_Attribute *attrs, uint32_t attr_id,
		const void *buf, size_t len)
{
	attrs[*attr_count].attributeID = attr_id;
	attrs[*attr_count].content.ref.buffer = (void *)buf;
	attrs[*attr_count].content.ref.length = len;
	(*attr_count)++;
}

void add_attr_value(size_t *attr_count, TEE_Attribute *attrs,
		uint32_t attr_id, uint32_t value_a, uint32_t value_b)
{
	attrs[*attr_count].attributeID = attr_id;
	attrs[*attr_count].content.value.a = value_a;
	attrs[*attr_count].content.value.b = value_b;
	(*attr_count)++;
}

TEE_Result pack_attrs(const TEE_Attribute *attrs, uint32_t attr_count,
		uint8_t **buf, size_t *blen)
{
	struct tee_attr_packed *a;
	uint8_t *b;
	size_t bl;
	size_t n;

	*buf = NULL;
	*blen = 0;
	if (attr_count == 0)
		return TEE_SUCCESS;

	bl = sizeof(uint32_t) + sizeof(struct tee_attr_packed) * attr_count;
	for (n = 0; n < attr_count; n++) {
		if ((attrs[n].attributeID & TEE_ATTR_BIT_VALUE) != 0)
			continue; /* Only memrefs need to be updated */

		if (!attrs[n].content.ref.buffer)
			continue;

		/* Make room for padding */
		bl += ROUNDUP(attrs[n].content.ref.length, 4);
	}

	b = calloc(1, bl);
	if (!b)
		return TEE_ERROR_OUT_OF_MEMORY;

	*buf = b;
	*blen = bl;

	*(uint32_t *)(void *)b = attr_count;
	b += sizeof(uint32_t);
	a = (struct tee_attr_packed *)(void *)b;
	b += sizeof(struct tee_attr_packed) * attr_count;

	for (n = 0; n < attr_count; n++) {
		a[n].attr_id = attrs[n].attributeID;
		if (attrs[n].attributeID & TEE_ATTR_BIT_VALUE) {
			a[n].a = attrs[n].content.value.a;
			a[n].b = attrs[n].content.value.b;
			continue;
		}

		a[n].b = attrs[n].content.ref.length;

		if (!attrs[n].content.ref.buffer) {
			a[n].a = 0;
			continue;
		}

		memcpy(b, attrs[n].content.ref.buffer,
		       attrs[n].content.ref.length);

		/* Make buffer pointer relative to *buf */
		a[n].a = (uint32_t)(uintptr_t)(b - *buf);

		/* Round up to good alignment */
		b += ROUNDUP(attrs[n].content.ref.length, 4);
	}

	return TEE_SUCCESS;
}

static TEEC_Result free_transient_object(TEE_ObjectHandle obj)
{
	TEEC_Result res;
	TEEC_Operation op = {0};
	uint32_t ret_orig;

	assert((uintptr_t)obj <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)obj;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);
	res = TEEC_InvokeCommand(&KM_session, OTZ_KEYMASTER_CMD_ID_FREE_TRANSIENT_OBJ, &op,
				 &ret_orig);
	if (res != TEEC_SUCCESS) {
		LOG_D("Invoke OTZ_KEYMASTER_CMD_ID_FREE_TRANSIENT_OBJ failed with res(%x), ret_orig(%x)\n", res, ret_orig );
	}

	return res;
}

static TEE_Result allocate_transient_object(TEE_ObjectType obj_type, uint32_t obj_size, TEE_ObjectHandle* obj)
{
	TEEC_Result res;
	TEEC_Operation op = {0};
	uint32_t ret_orig;

	op.params[0].value.a = obj_type;
	op.params[0].value.b = obj_size;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_OUTPUT,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(&KM_session,
				 OTZ_KEYMASTER_CMD_ID_ALLOCATE_TRANSIENT_OBJ,
				 &op,
				 &ret_orig);

	if (res != TEEC_SUCCESS) {
		LOG_D("Invoke OTZ_KEYMASTER_CMD_ID_ALLOCATE_TRANSIENT_OBJ failed with res(%x), ret_orig(%x)\n", res, ret_orig );
	}

	if (res == TEEC_SUCCESS)
		*obj = (TEE_ObjectHandle)(uintptr_t)op.params[1].value.a;

	return res;
}

TEEC_Result populate_transient_object(TEE_ObjectHandle o, const TEE_Attribute *attrs, uint32_t attr_count)
{
	TEEC_Result res;
	TEEC_Operation op = {0};
	uint32_t ret_orig;
	uint8_t *buf;
	size_t blen;

	res = pack_attrs(attrs, attr_count, &buf, &blen);
	if (res != TEEC_SUCCESS) {
		LOG_D(" pack_attrs failed. (%x)", res);
		return res;
	}

	assert((uintptr_t)o <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)o;

	op.params[1].tmpref.buffer = buf;
	op.params[1].tmpref.size = blen;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(&KM_session, OTZ_KEYMASTER_CMD_ID_POPULATE_TRANSIENT_OBJ, &op,
				 &ret_orig);

	if (res != TEEC_SUCCESS) {
		LOG_D("Invoke  failed with res(%x), ret_orig(%x)\n", res, ret_orig );
	}

	free(buf);
	return res;
}

TEEC_Result allocate_operation(TEE_OperationHandle *oph,
		uint32_t algo, uint32_t mode,
		uint32_t max_key_size)
{
	TEEC_Result res;
	TEEC_Operation op = {0};
	uint32_t ret_orig;

	op.params[0].value.a = 0;
	op.params[0].value.b = algo;
	op.params[1].value.a = mode;
	op.params[1].value.b = max_key_size;

	//LOG_D("algo(%x), mode(%x) max_key_size(%x)\n", algo, mode, max_key_size);
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_VALUE_INPUT,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(&KM_session, OTZ_KEYMASTER_CMD_ID_ALLOCATE_OPERATION, &op,
				 &ret_orig);

	if (res == TEEC_SUCCESS) {
		*oph = (TEE_OperationHandle)(uintptr_t)op.params[0].value.a;
	}
	else {
		LOG_D("Invoke OTZ_KEYMASTER_CMD_ID_ALLOCATE_OPERATION failed with res(%x), ret_orig(%x)\n", res, ret_orig );
	}

	return res;
}

TEEC_Result free_operation(TEE_OperationHandle oph)
{
	TEEC_Result res;
	TEEC_Operation op = {0};
	uint32_t ret_orig;

	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(&KM_session, OTZ_KEYMASTER_CMD_ID_FREE_OPERATION, &op,
				 &ret_orig);

	if (res != TEEC_SUCCESS) {
		LOG_D("Invoke OTZ_KEYMASTER_CMD_ID_FREE_OPERATION failed with res(%x), ret_orig(%x)\n", res, ret_orig );
	}

	return res;
}

TEE_Result set_operation_key(TEE_OperationHandle oph, TEE_ObjectHandle key)
{
	TEEC_Result res;
	TEEC_Operation op = {0};
	uint32_t ret_orig;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	assert((uintptr_t)key <= UINT32_MAX);
	op.params[0].value.b = (uint32_t)(uintptr_t)key;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(&KM_session, OTZ_KEYMASTER_CMD_ID_SET_OPERATION_KEY, &op,
				 &ret_orig);

	if (res != TEEC_SUCCESS) {
		LOG_D("Invoke OTZ_KEYMASTER_CMD_ID_SET_OPERATION_KEY failed with res(%x), ret_orig(%x)\n", res, ret_orig );
	}

	return res;
}

TEEC_Result Initialize_ca(void)
{
	TEEC_Result result;
	TEEC_UUID svc_id = KEYMASTER_UUID;
	TEEC_Operation operation;
	uint32_t err_origin;

	memset(&operation, 0, sizeof(operation));
	if (KM_inited) {
		LOG_D("%s:%d: KM_session has been inited. Skip it!\n", __func__, __LINE__);
		return 0;
	}

	/* Initialize Context */
	result = TEEC_InitializeContext(NULL, &KM_context);

	if (result != TEEC_SUCCESS) {
		LOG_D("TEEC_InitializeContext failed with error = %x\n", result);
		return result;
	}
	/* Open Session */
	result = TEEC_OpenSession(&KM_context, &KM_session, &svc_id,
				  TEEC_LOGIN_PUBLIC,
				  NULL, NULL,
				  &err_origin);

	if (result != TEEC_SUCCESS) {
		LOG_D("TEEC_Opensession failed with code 0x%x origin 0x%x",result, err_origin);
		TEEC_FinalizeContext(&KM_context);
		return result;
	}
	/* Init TA */
	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
						TEEC_NONE, TEEC_NONE);
	operation.started = 1;

	result = TEEC_InvokeCommand(&KM_session,
				    OTZ_KEYMASTER_CMD_ID_INIT,
				    &operation,
				    NULL);

	KM_inited = true;
	return result;
}

TEEC_Result Terminate_ca(void)
{
	TEEC_Operation operation;
	TEEC_Result result;

	if (false == KM_inited) {
		LOG_D("Warning: This session has been terminated before. It's likely wrong.");
		LOG_D("Warning: Please check if control flow is messed up");
		return 0;
	}

	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
			TEEC_NONE, TEEC_NONE);
	operation.started = 1;
	result = TEEC_InvokeCommand(&KM_session,
			OTZ_KEYMASTER_CMD_ID_TERM,
			&operation,
			NULL);

	TEEC_CloseSession(&KM_session);
	TEEC_FinalizeContext(&KM_context);

	KM_inited = false;
	return result;
}

bool get_ca_inited()
{
	return KM_inited;
}

TEEC_Result asymmetric_sign_tee_ca(
		TEE_OperationHandle oph,
		TEE_OperationMode op_mode,
		const TEE_Attribute *params,
		uint32_t paramCount,
		const void *src,
		size_t src_len,
		void *dst,
		size_t *dst_len)
{
	TEEC_Result res;
	TEEC_Operation op = {0};
	uint32_t ret_orig;
	uint8_t *buf;
	size_t blen;

	res = pack_attrs(params, paramCount, &buf, &blen);
	if (res != TEE_SUCCESS) {
		LOG_D(" pack_attrs failed with res(%x)", res);
		return res;
	}

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;
	op.params[0].value.b = (uint32_t)op_mode;

	op.params[1].tmpref.buffer = buf;
	op.params[1].tmpref.size = blen;

	op.params[2].tmpref.buffer = (void *)src;
	op.params[2].tmpref.size = src_len;

	op.params[3].tmpref.buffer = dst;
	op.params[3].tmpref.size = *dst_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT);

	res = TEEC_InvokeCommand(&KM_session, OTZ_KEYMASTER_CMD_ID_SIGN_DIGEST, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		LOG_D("Invoke OTZ_KEYMASTER_CMD_ID_SIGN_DIGEST failed with res(%x), ret_orig(%x)\n", res, ret_orig );
	}

	if (res == TEEC_SUCCESS) {
		*dst_len = op.params[3].tmpref.size;
	}
	free(buf);
	return res;
}

TEEC_Result asymmetric_en_de_crypt_tee_ca(
		TEE_OperationHandle oph,
		TEE_OperationMode op_mode,
		const TEE_Attribute *params,
		uint32_t paramCount,
		const void *src,
		size_t src_len,
		void *dst,
		size_t *dst_len)
{
	TEEC_Result res;
	TEEC_Operation op = {0};
	uint32_t ret_orig;
	uint8_t *buf;
	size_t blen;

	res = pack_attrs(params, paramCount, &buf, &blen);
	if (res != TEE_SUCCESS) {
		LOG_D(" pack_attrs failed with res(%x)", res);
		return res;
	}

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;
	op.params[0].value.b = (uint32_t)op_mode;

	op.params[1].tmpref.buffer = buf;
	op.params[1].tmpref.size = blen;

	op.params[2].tmpref.buffer = (void *)src;
	op.params[2].tmpref.size = src_len;

	op.params[3].tmpref.buffer = dst;
	op.params[3].tmpref.size = *dst_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT);

	res = TEEC_InvokeCommand(&KM_session, OTZ_KEYMASTER_CMD_ID_ASYMMETRIC_EN_DE_CRYPT, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		LOG_D("Invoke OTZ_KEYMASTER_CMD_ID_ASYMMETRIC_CRYPT failed with res(%x), ret_orig(%x)\n", res, ret_orig );
	}

	if (res == TEEC_SUCCESS) {
		*dst_len = op.params[3].tmpref.size;
	}
	free(buf);
	return res;
}

TEEC_Result asymmetric_verify_tee_ca(TEE_OperationHandle oph,
				     TEE_OperationMode op_mode,
				     const TEE_Attribute *params,
				     uint32_t paramCount,
				     const void *digest,
				     size_t digest_len,
				     const void *signature,
				     size_t signature_len)
{
	TEEC_Result res;
	TEEC_Operation op = {0};
	uint32_t ret_orig;
	uint8_t *buf;
	size_t blen;

	res = pack_attrs(params, paramCount, &buf, &blen);
	if (res != TEE_SUCCESS) {
		LOG_D("pack_attrs failed with res(%x)\n", res);
		return res;
	}

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;
	op.params[0].value.b = (uint32_t)op_mode;

	op.params[1].tmpref.buffer = buf;
	op.params[1].tmpref.size = blen;

	op.params[2].tmpref.buffer = (void *)digest;
	op.params[2].tmpref.size = digest_len;

	op.params[3].tmpref.buffer = (void *)signature;
	op.params[3].tmpref.size = signature_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT);

	res = TEEC_InvokeCommand(&KM_session, OTZ_KEYMASTER_CMD_ID_VERIFY_SIGNATURE,
				 &op, &ret_orig);
	if (res != TEEC_SUCCESS) {
		LOG_D("Invoke OTZ_KEYMASTER_CMD_ID_VERIFY_SIGNATURE failed with res(%x), ret_orig(%x)\n", res, ret_orig );
	}

	free(buf);
	return res;
}

static TEEC_Result generate_key_tee_ca(
        const uint32_t tee_obj_type,
        uint32_t key_size,
        uint8_t *id,
        uint32_t id_len,
		const TEE_Attribute *params,
		uint32_t paramCount)
{
	TEEC_Result res;
	TEEC_Operation op = {0};
	uint32_t ret_orig;
	uint8_t *buf;
	size_t blen;

	res = pack_attrs(params, paramCount, &buf, &blen);
	if (res != TEE_SUCCESS) {
		LOG_D(" pack_attrs failed. (%x)", res);
		return res;
	}

	assert((uintptr_t)obj <= UINT32_MAX);
	op.params[0].value.a = tee_obj_type;
	op.params[0].value.b = key_size;

	op.params[1].tmpref.buffer = buf;
	op.params[1].tmpref.size = blen;

	op.params[2].tmpref.buffer = id;
	op.params[2].tmpref.size = id_len;

    op.paramTypes = TEEC_PARAM_TYPES(
                TEEC_VALUE_INPUT,
                TEEC_MEMREF_TEMP_INPUT,
                TEEC_MEMREF_TEMP_OUTPUT,
                TEEC_NONE);

	res = TEEC_InvokeCommand(&KM_session,
				OTZ_KEYMASTER_CMD_ID_GENERATE_KEYPAIR,
				&op,
				&ret_orig);
	if (res != TEEC_SUCCESS) {
		LOG_D("Invoke OTZ_KEYMASTER_CMD_ID_GENERATE_KEYPAIR failed with res(%x), ret_orig(%x)\n", res, ret_orig );
	}

	free(buf);
	return res;
}

TEEC_Result generate_dsa_keypair_ca(uint8_t *id, uint32_t id_len,
        const keymaster_dsa_keygen_params_t* dsa_params)
{

	TEE_Attribute attrs[4];
	TEEC_Result res = TEEC_ERROR_GENERIC;
	size_t attr_count = 0;

	memset(attrs,0x0, sizeof(attrs));
	/* prime (p) */
	if (dsa_params->prime_p && dsa_params->prime_p_len) {
		add_attr(&attr_count, attrs, TEE_ATTR_DSA_PRIME,
				dsa_params->prime_p, dsa_params->prime_p_len);
	}
	/* prime (q) */
	if (dsa_params->prime_q && dsa_params->prime_q_len) {
		add_attr(&attr_count, attrs, TEE_ATTR_DSA_SUBPRIME,
				dsa_params->prime_q, dsa_params->prime_q_len);
	}
	/* generator (base) */
	if (dsa_params->generator && dsa_params->generator_len) {
		add_attr(&attr_count, attrs, TEE_ATTR_DSA_BASE,
				dsa_params->generator, dsa_params->generator_len);
	}

	res = generate_key_tee_ca(TEE_TYPE_DSA_KEYPAIR, dsa_params->key_size,
            id, id_len, attrs, attr_count);
	if (res != TEEC_SUCCESS) {
		LOG_D("%s:%d: generate_key_tee_ca failed.(%x)", __func__, __LINE__, res);
		goto error;
	}
error:
	return res;

}

static uint32_t ecdsa_get_curve_tee(const uint32_t field_size) {
	uint32_t curve = 0xFF;

	switch (field_size) {
		case 192:
			curve = TEE_ECC_CURVE_NIST_P192;
			break;
		case 224:
			curve = TEE_ECC_CURVE_NIST_P224;
			break;
		case 256:
			curve = TEE_ECC_CURVE_NIST_P256;
			break;
		case 384:
			curve = TEE_ECC_CURVE_NIST_P384;
			break;
		case 521:
			curve = TEE_ECC_CURVE_NIST_P521;
			break;
		default:
			curve = 0xFF;
			break;
	}
	return curve;
}

TEEC_Result get_keypair_public_ca(const TEE_ObjectHandle handle,
				 uint8_t** x509_data, size_t* x509_data_len)
{
	TEE_Result res = TEEC_SUCCESS;
	TEEC_Operation op;
	uint32_t ret_orig;
	uint8_t buf[1024] = {0};
	size_t blen = sizeof(buf);

	assert((uintptr_t)o <= UINT32_MAX);
	memset(&op, 0, sizeof(op));
	op.params[0].value.a = (uint32_t)(uintptr_t)handle;

	op.params[1].tmpref.buffer = buf;
	op.params[1].tmpref.size = blen;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(&KM_session, OTZ_KEYMASTER_CMD_ID_GET_KEYPAIR_PUBLIC,
				 &op, &ret_orig);
	if (res != TEEC_SUCCESS) {
		LOG_D("%s:%d: Invoke OTZ_KEYMASTER_CMD_ID_GET_KEYPAIR_PUBLIC failed with res(%x), ret_orig(%x)\n", __func__, __LINE__, res, ret_orig);
	}
	else {
		blen = op.params[1].tmpref.size;
		*x509_data = (uint8_t*)malloc(blen);
		if (*x509_data == NULL) {
			LOG_D("Failed allocate buffer for x509 data!\n");
		}
		memcpy(*x509_data, buf, blen);
		*x509_data_len = blen;
	}

	return res;
}

TEEC_Result delete_key_ca(const uint8_t *id, uint32_t id_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = {0};
	uint32_t ret_orig;
	int ret = -1; /* Default */

	/* Sanity Check */
	if (KM_inited == 0) {
		LOG_D("%s:%d: KM_session is not inited.\n", __func__, __LINE__);
		goto out;
	}

	op.params[0].tmpref.buffer = (void *)id;
	op.params[0].tmpref.size = id_len;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	/* Delete Keypair */
	res = TEEC_InvokeCommand(&KM_session, OTZ_KEYMASTER_CMD_ID_DELETE_KEYPAIR, &op, &ret_orig);
	if (res != TEEC_SUCCESS) {
		LOG_D("Invoke OTZ_KEYMASTER_CMD_ID_DELETE_KEYPAIR failed with res(%x), ret_orig(%x)\n", res, ret_orig);
		goto out;
	}
	ret = 0;
out:
	return ret;
}

TEEC_Result load_key_ca(TEE_ObjectHandle *key, const uint8_t *id, uint32_t id_len,
        uint32_t obj_type, uint32_t key_len)
{
    TEEC_Result res = TEEC_ERROR_GENERIC;
    TEEC_Operation op = {0};
    uint32_t ret_orig;
    int ret = -1; /* Default */

    /* Sanity Check */
    if (KM_inited == 0) {
        LOG_D("%s:%d: KM_session is not inited.\n", __func__, __LINE__);
        goto out;
    }

    op.params[0].tmpref.buffer = (void *)id;
    op.params[0].tmpref.size = id_len;
    op.params[1].value.a = obj_type;
    op.params[1].value.b = key_len;
    op.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INPUT,
            TEEC_VALUE_OUTPUT, TEEC_NONE);

    /* Load Keypair */
    res = TEEC_InvokeCommand(&KM_session, OTZ_KEYMASTER_CMD_ID_LOAD_KEY, &op, &ret_orig);
    if (res != TEEC_SUCCESS) {
        LOG_D("Invoke OTZ_KEYMASTER_CMD_ID_LOAD_KEY failed with res(%x), ret_orig(%x)\n", res, ret_orig);
        goto out;
    } else {
        *key = (TEE_ObjectHandle)op.params[2].value.a;
    }
    ret = 0;
out:
    return ret;
}

TEEC_Result release_key_ca(TEE_ObjectHandle key)
{
    TEEC_Result res = TEEC_ERROR_GENERIC;
    TEEC_Operation op = {0};
    uint32_t ret_orig;
    int ret = -1; /* Default */

    /* Sanity Check */
    if (KM_inited == 0) {
        LOG_D("%s:%d: KM_session is not inited.\n", __func__, __LINE__);
        goto out;
    }

    res = free_transient_object(key);
    if (res != TEEC_SUCCESS) {
        goto out;
    }
    ret = 0;

out:
    return ret;
}

TEEC_Result query_key_existence_ca(const TEE_ObjectHandle handle)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op;
	uint32_t ret_orig;

	/* Sanity Check */
	if (false == get_ca_inited()) {
		LOG_D("%s:%d: KM_session is not inited.\n", __func__, __LINE__);
		goto out;
	}

	if (handle == NULL) {
		LOG_D("%s:%d: Invalid input\n", __func__, __LINE__);
		goto out;
	}

	assert((uintptr_t)handle <= UINT32_MAX);
	memset(&op, 0, sizeof(op));
	op.params[0].value.a = (uint32_t)(uintptr_t)handle;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	/* Delete Keypair */
	res = TEEC_InvokeCommand(&KM_session, OTZ_KEYMASTER_CMD_ID_QUERY_KEY_EXISTENCE, &op, &ret_orig);
	if (res != TEEC_SUCCESS) {
		LOG_D("Invoke OTZ_KEYMASTER_CMD_ID_QUERY_KEY_EXISTENCE failed with res(%x), ret_orig(%x)\n", res, ret_orig);
		goto out;
	}
out:
	return res;
}

TEEC_Result generate_symmetric_key(uint8_t *id, uint32_t id_len,
					const uint32_t key_len,
					const uint32_t tee_obj_type)
{
	TEE_Attribute attrs[4];
	TEEC_Result res = TEEC_ERROR_GENERIC;
	size_t attr_count = 0;

	memset(attrs,0x0, sizeof(attrs));
	res = generate_key_tee_ca(tee_obj_type, key_len, id, id_len, attrs, attr_count);
	if (res != TEEC_SUCCESS) {
		LOG_D("Error: generate_key_tee_ca failed.(%x)\n", res);
	}
error:
	return res;
}

TEEC_Result generate_ec_keypair(uint8_t *id, uint32_t id_len, const keymaster_ec_keygen_params_t* ec_params)
{
	TEE_Attribute attrs[4];
	TEEC_Result res = TEEC_ERROR_GENERIC;
	size_t attr_count = 0;

	memset(attrs,0x0, sizeof(attrs));
	/* field size */
	if (ec_params->field_size) {
		uint32_t curve = 0;
		curve = ecdsa_get_curve_tee(ec_params->field_size);
		//TODO: which attr need to be filled with field_size
		add_attr_value(&attr_count, attrs, TEE_ATTR_ECC_CURVE,
				curve, 0);
	}
	res = generate_key_tee_ca(TEE_TYPE_ECDSA_KEYPAIR, ec_params->field_size,
            id, id_len, attrs, attr_count);
	if (res != TEEC_SUCCESS) {
		LOG_D("Error: generate_key_tee_ca failed.(%x)\n", res);
	}
error:
	return res;
}

TEEC_Result generate_rsa_keypair_ca(uint8_t *id, uint32_t id_len,
        const keymaster_rsa_keygen_params_t* rsa_params)
{
	TEE_Attribute attrs[4];
	TEEC_Result res = TEEC_ERROR_GENERIC;
	size_t attr_count = 0;

	memset(attrs, 0x0, sizeof(attrs));
	if (rsa_params->modulus_size) {
		add_attr(&attr_count, attrs, TEE_ATTR_RSA_MODULUS,
				&(rsa_params->modulus_size), sizeof(rsa_params->modulus_size));
	}

	if (rsa_params->public_exponent) {
		uint32_t temp = TEE_U32_TO_BIG_ENDIAN(rsa_params->public_exponent);
		add_attr(&attr_count, attrs, TEE_ATTR_RSA_PUBLIC_EXPONENT,
			 &temp, 4);
	}
	res = generate_key_tee_ca(TEE_TYPE_RSA_KEYPAIR, rsa_params->modulus_size, id, id_len,
            attrs, attr_count);
	if (res != TEEC_SUCCESS) {
		LOG_D("Error: generate_key_tee_ca failed.(%x)", res);
	}
error:
	return res;
}

TEEC_Result digest_update_ca(TEE_OperationHandle oph,
				 const void *chunk,
				 size_t chunk_size)
{
	TEEC_Result res;
	TEEC_Operation op = {0};
	uint32_t ret_orig;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;
	op.params[1].tmpref.buffer = (void *)chunk;
	op.params[1].tmpref.size = chunk_size;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(&KM_session, OTZ_KEYMASTER_CMD_ID_DIGEST_UPDATE, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		LOG_D("Invoke OTZ_KEYMASTER_CMD_ID_DIGEST_UPDATE failed with res(%x), ret_orig(%x)\n",
				res, ret_orig );
	}

	return res;
}

TEEC_Result digest_do_final_ca(TEE_OperationHandle oph,
		const void *chunk,
		size_t chunk_len, void *hash,
		size_t *hash_len)
{
	TEEC_Result res;
	TEEC_Operation op = {0};
	uint32_t ret_orig;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = (void *)chunk;
	op.params[1].tmpref.size = chunk_len;

	op.params[2].tmpref.buffer = (void *)hash;
	op.params[2].tmpref.size = *hash_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
			TEEC_MEMREF_TEMP_INPUT,
			TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(&KM_session, OTZ_KEYMASTER_CMD_ID_DIGEST_DO_FINAL, &op,
			&ret_orig);

	if (res != TEEC_SUCCESS) {
		LOG_D("Invoke OTZ_KEYMASTER_CMD_ID_DIGEST_DO_FINAL failed with res(%x), ret_orig(%x)\n", res, ret_orig );
	}

	if (res == TEEC_SUCCESS)
		*hash_len = op.params[2].tmpref.size;

	return res;
}

TEEC_Result do_import_keypair_tee_ca(
        const uint8_t* key, const size_t key_file_len,
        const uint32_t key_type, const uint32_t real_key_bits,
        uint8_t *id, uint32_t id_len)
{
    TEE_Attribute attrs[4];
    size_t attr_count = 0;
    TEEC_Result res;
    TEEC_Operation op = {0};
    uint32_t ret_orig;
    uint8_t *buf = NULL;
    size_t blen;
    uint32_t tee_attr_type = 0;

    /* Init attrs buffer */
    memset(attrs, 0x0, sizeof(attrs));
    if (key_type == TEE_TYPE_ECDSA_KEYPAIR) {
        uint32_t curve = 0;
        /* pack raw data */
        add_attr(&attr_count, attrs, TEE_ATTR_PKCS8_BASE, key, key_file_len);
        /* pack curve */
        curve = ecdsa_get_curve_tee(real_key_bits);
        add_attr_value(&attr_count, attrs, TEE_ATTR_ECC_CURVE, curve, 0);
    } else if (key_type == TEE_TYPE_RSA_KEYPAIR) {
        /* pack raw data */
        add_attr(&attr_count, attrs, TEE_ATTR_PKCS8_BASE, key, key_file_len);
    }
    /* Pack Attrs */
    res = pack_attrs(attrs, attr_count, &buf, &blen);
    if (res != TEE_SUCCESS) {
        LOG_D("%s:%d: pack_attrs failed. (%x)", __func__, __LINE__, res);
        goto out;
    }
    /* Prepare TEE Operation */
    op.params[0].value.a = key_type;
    op.params[0].value.b = real_key_bits;

    op.params[1].tmpref.buffer = buf;
    op.params[1].tmpref.size = blen;

    op.params[2].tmpref.buffer = id;
    op.params[2].tmpref.size = id_len;

    op.paramTypes = TEEC_PARAM_TYPES(
            TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT,
            TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);

    res = TEEC_InvokeCommand(&KM_session, OTZ_KEYMASTER_CMD_ID_IMPORT_KEYPAIR, &op,
            &ret_orig);
    if (res != TEEC_SUCCESS) {
        LOG_D("Invoke OTZ_KEYMASTER_CMD_ID_IMPORT_KEYPAIR failed with res(%x), ret_orig(%x)\n", res, ret_orig );
        goto out;
    }

out:
    if (buf) free(buf);
    return res;
}

TEEC_Result do_import_symmetric_key_tee_ca(
        const uint8_t* key,
        const size_t key_len,
        const uint32_t key_type,
        uint8_t *id, uint32_t id_len)
{
    TEE_Attribute attrs[4];
    size_t attr_count = 0;
    TEEC_Result res;
    TEEC_Operation op = {0};
    uint32_t ret_orig;
    uint8_t *buf = NULL;
    size_t blen;
    uint32_t tee_attr_type = 0;

    /* Init attrs buffer */
    memset(attrs, 0x0, sizeof(attrs));
    /* symmetric key */
    add_attr(&attr_count, attrs, TEE_ATTR_SECRET_VALUE, key, key_len);
    /* Pack Attrs */
    res = pack_attrs(attrs, attr_count, &buf, &blen);
    if (res != TEE_SUCCESS) {
        LOG_D("%s:%d: pack_attrs failed. (%x)", __func__, __LINE__, res);
        goto out;
    }
    /* Prepare TEE Operation */
    op.params[0].value.a = key_type;
    op.params[0].value.b = key_len * 8;

    op.params[1].tmpref.buffer = buf;
    op.params[1].tmpref.size = blen;

    op.params[2].tmpref.buffer = id;
    op.params[2].tmpref.size = id_len;

    op.paramTypes = TEEC_PARAM_TYPES(
            TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT,
            TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);

    res = TEEC_InvokeCommand(&KM_session, OTZ_KEYMASTER_CMD_ID_IMPORT_SYMMETRIC_KEY, &op,
            &ret_orig);
    if (res != TEEC_SUCCESS) {
        LOG_D("Invoke OTZ_KEYMASTER_CMD_ID_IMPORT_SYMMETRIC_KEY failed with res(%x), ret_orig(%x)\n", res, ret_orig );
        goto out;
    }

out:
    if (buf) free(buf);
    return res;
}

TEEC_Result digest_init_ca(const uint32_t main_algo,
			       TEE_OperationHandle* op, uint32_t digest_algo) {

	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEE_OperationHandle digest_op = TEE_HANDLE_NULL;
	uint32_t hash_algo = 0;

	if (TEE_ALG_GET_MAIN_ALG(main_algo) == TEE_MAIN_ALGO_ECDSA) {
        hash_algo = digest_algo;
	} else {
		hash_algo = TEE_ALG_HASH_ALGO(TEE_ALG_GET_DIGEST_HASH(main_algo));
	}

	/* Prepare digest handle */
	res = allocate_operation(&digest_op, hash_algo, TEE_MODE_DIGEST, 0);
	if (res != TEEC_SUCCESS) {
		LOG_D("allocate_operation failed with res(%x)\n", res);
		goto out;
	}
	*op = digest_op;
out:
	return res;
}

TEEC_Result hmac_keyblob_init_ca(
		const uint32_t hmac_algo,
		const uint32_t hmac_obj_type,
		TEE_OperationHandle* op)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op_mac = {0};
	uint32_t ret_orig;

	op_mac.params[0].value.a = hmac_algo;
	op_mac.params[0].value.b = hmac_obj_type;
	op_mac.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_OUTPUT,
			TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(&KM_session, OTZ_KEYMASTER_CMD_ID_MAC_KEYBLOB_INIT, &op_mac, &ret_orig);
	if (res != TEEC_SUCCESS) {
		LOG_D("Invoke OTZ_KEYMASTER_CMD_ID_MAC_KEYBLOB_INIT failed with res(%x), ret_orig(%x)\n", res, ret_orig);
	} else {
        *op = (TEE_OperationHandle)(uintptr_t)op_mac.params[1].value.a;
    }

out:
	return res;
}

TEEC_Result hmac_init_ca(
		const uint32_t hmac_algo,
		TEE_OperationHandle* op,
		TEE_ObjectHandle key,
		uint32_t key_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op_mac = {0};
	uint32_t ret_orig;

	/* Prepare mac handle */
	res = allocate_operation(op, hmac_algo, TEE_MODE_MAC, key_len);
	if (res != TEEC_SUCCESS) {
		LOG_D("allocate_operation failed with res(%x)\n", res);
		goto out;
	}

	res = set_operation_key(*op, key);
	if (res != TEEC_SUCCESS) {
		LOG_D("set_operation_key failed with res(%x)\n", res);
		goto out;
	}

	op_mac.params[0].value.a = (uint32_t)(uintptr_t)*op;
	op_mac.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
			TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(&KM_session, OTZ_KEYMASTER_CMD_ID_MAC_INIT, &op_mac, &ret_orig);
	if (res != TEEC_SUCCESS) {
		LOG_D("Invoke OTZ_KEYMASTER_CMD_ID_MAC_INIT failed with res(%x), ret_orig(%x)\n", res, ret_orig);
	}

out:
	return res;
}

TEEC_Result hmac_update_ca(
		TEE_OperationHandle oph,
		const void *chunk,
		size_t chunk_size)
{
	TEEC_Result res;
	TEEC_Operation op = {0};
	uint32_t ret_orig;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;
	op.params[1].tmpref.buffer = (void *)chunk;
	op.params[1].tmpref.size = chunk_size;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
			TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
			TEEC_NONE);

	res = TEEC_InvokeCommand(&KM_session, OTZ_KEYMASTER_CMD_ID_MAC_UPDATE, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		LOG_D("Invoke OTZ_KEYMASTER_CMD_ID_MAC_UPDATE failed with res(%x), ret_orig(%x)\n",
				res, ret_orig );
	}

	return res;
}

TEEC_Result hmac_do_final_ca(
        TEE_OperationHandle oph,
        const void *chunk,
        size_t chunk_len, void *hash,
        size_t *hash_len)
{
	TEEC_Result res;
	TEEC_Operation op = {0};
	uint32_t ret_orig;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = (void *)chunk;
	op.params[1].tmpref.size = chunk_len;

	op.params[2].tmpref.buffer = (void *)hash;
	op.params[2].tmpref.size = *hash_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
			TEEC_MEMREF_TEMP_INPUT,
			TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(&KM_session, OTZ_KEYMASTER_CMD_ID_MAC_DO_FINAL, &op,
			&ret_orig);

	if (res != TEEC_SUCCESS) {
		LOG_D("Invoke OTZ_KEYMASTER_CMD_ID_DIGEST_DO_FINAL failed with res(%x), ret_orig(%x)\n", res, ret_orig );
	}

	if (res == TEEC_SUCCESS)
		*hash_len = op.params[2].tmpref.size;

	return res;
}

TEEC_Result hmac_do_final_compare_ca(
        TEE_OperationHandle oph,
        const void *chunk,
        size_t chunk_len, const void *hash,
        size_t hash_len)
{
	TEEC_Result res;
	TEEC_Operation op = {0};
	uint32_t ret_orig;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = (void *)chunk;
	op.params[1].tmpref.size = chunk_len;

	op.params[2].tmpref.buffer = (void *)hash;
	op.params[2].tmpref.size = hash_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
			TEEC_MEMREF_TEMP_INPUT,
			TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(&KM_session, OTZ_KEYMASTER_CMD_ID_MAC_DO_FINAL_COMPARE, &op,
			&ret_orig);

	if (res != TEEC_SUCCESS) {
		LOG_D("Invoke OTZ_KEYMASTER_CMD_ID_DIGEST_DO_FINAL_COMPARE failed with res(%x), ret_orig(%x)\n", res, ret_orig );
	}

	return res;
}

TEEC_Result cipher_init_ca(TEE_OperationHandle oph,
		const void *iv, size_t iv_len)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t ret_orig;

	assert((uintptr_t)oph <= UINT32_MAX);
	memset(&op, 0, sizeof(op));
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	if (iv != NULL) {
		op.params[1].tmpref.buffer = (void *)iv;
		op.params[1].tmpref.size = iv_len;

		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
						 TEEC_MEMREF_TEMP_INPUT,
						 TEEC_NONE, TEEC_NONE);
	} else {
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
						 TEEC_NONE, TEEC_NONE);
	}

	res = TEEC_InvokeCommand(&KM_session, OTZ_KEYMASTER_CMD_ID_CIPHER_INIT, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		LOG_D("Invoke OTZ_KEYMASTER_CMD_ID_CIPHER_INIT failed with res(%x), ret_orig(%x)\n", res, ret_orig);
	}

	return res;
}

TEEC_Result cipher_update_ca(TEE_OperationHandle oph,
		const void *src, size_t src_len,
        void *dst, size_t *dst_len, const uint32_t need_buffing)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t ret_orig;

	assert((uintptr_t)oph <= UINT32_MAX);
	memset(&op, 0, sizeof(op));
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;
	op.params[0].value.b = (uint32_t)need_buffing;

	op.params[1].tmpref.buffer = (void *)src;
	op.params[1].tmpref.size = src_len;

	op.params[2].tmpref.buffer = dst;
	op.params[2].tmpref.size = *dst_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(&KM_session, OTZ_KEYMASTER_CMD_ID_CIPHER_UPDATE, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		LOG_D("Invoke OTZ_KEYMASTER_CMD_ID_CIPHER_UPDATE failed with res(%x), ret_orig(%x)\n", res, ret_orig);
	}

	if (res == TEEC_SUCCESS)
		*dst_len = op.params[2].tmpref.size;

	return res;
}

TEEC_Result cipher_do_final_ca(TEE_OperationHandle oph,
				   const void *src, size_t src_len,
				   void *dst, size_t *dst_len)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t ret_orig;

	assert((uintptr_t)oph <= UINT32_MAX);
	memset(&op, 0, sizeof(op));
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = (void *)src;
	op.params[1].tmpref.size = src_len;

	op.params[2].tmpref.buffer = (void *)dst;
	op.params[2].tmpref.size = *dst_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(&KM_session, OTZ_KEYMASTER_CMD_ID_CIPHER_DO_FINAL, &op,
				 &ret_orig);

	if (res != TEEC_SUCCESS) {
		LOG_D("Invoke OTZ_KEYMASTER_CMD_ID_CIPHER_DO_FINAL failed with res(%x), ret_orig(%x)\n", res, ret_orig);
	}

	if (res == TEEC_SUCCESS)
		*dst_len = op.params[2].tmpref.size;

	return res;
}

TEEC_Result export_key(
		const uint8_t *id, uint32_t id_len,
        uint32_t obj_type, uint32_t key_len,
		uint8_t** x509_data, size_t* x509_data_len)
{
	TEE_Result res = TEEC_SUCCESS;
	TEEC_Operation op = {0};
	uint32_t ret_orig;
	uint8_t buf[1024] = {0};
	size_t blen = sizeof(buf);

	op.params[0].tmpref.buffer = (void *)id;
	op.params[0].tmpref.size = id_len;
	op.params[1].tmpref.buffer = buf;
	op.params[1].tmpref.size = blen;
	op.params[2].value.a = obj_type;
	op.params[2].value.b = key_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_VALUE_INPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(&KM_session, OTZ_KEYMASTER_CMD_ID_GET_KEYPAIR_PUBLIC,
				 &op, &ret_orig);
	if (res != TEEC_SUCCESS) {
		LOG_D("%s:%d: Invoke OTZ_KEYMASTER_CMD_ID_GET_KEYPAIR_PUBLIC failed with res(%x),\
            ret_orig(%x)\n", __func__, __LINE__, res, ret_orig);
	} else {
		blen = op.params[1].tmpref.size;
		*x509_data = (uint8_t*)malloc(blen);
		if (*x509_data == NULL) {
			LOG_D("Failed allocate buffer for x509 data!\n");
		}
		memcpy(*x509_data, buf, blen);
		*x509_data_len = blen;
	}
	return res;
}

TEEC_Result tee_ae_init(const TEE_OperationHandle oph,
                           const void *nonce, size_t nonce_len,
                           size_t tag_len, size_t aad_len,
                           size_t payload_len)
{
	TEEC_Result res;
	TEEC_Operation op = {0};
	uint32_t ret_orig;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;
	op.params[0].value.b = tag_len;

	op.params[1].tmpref.buffer = (void *)nonce;
	op.params[1].tmpref.size = nonce_len;

	op.params[2].value.a = aad_len;
	op.params[2].value.b = payload_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_VALUE_INPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(&KM_session, OTZ_KEYMASTER_CMD_ID_AE_INIT, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		LOG_D("Invoke OTZ_KEYMASTER_CMD_ID_AE_INIT failed with res(%x), ret_orig(%x)\n", res, ret_orig);
	}
	return res;
}

TEEC_Result tee_ae_update_aad(const TEE_OperationHandle oph,
					      const void *aad, size_t aad_len)
{
	TEEC_Result res;
	TEEC_Operation op = {0};
	uint32_t ret_orig;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = (void *)aad;
	op.params[1].tmpref.size = aad_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(&KM_session, OTZ_KEYMASTER_CMD_ID_AE_UPDATE_AAD, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		LOG_D("Invoke OTZ_KEYMASTER_CMD_ID_AE_UPDATE_AAD failed with res(%x), ret_orig(%x)\n", res, ret_orig);
	}

	return res;
}

TEEC_Result tee_ae_update(const TEE_OperationHandle oph,
                             const void *src, size_t src_len,
                             void *dst, size_t *dst_len,
                             const uint32_t need_buffering)
{
	TEEC_Result res;
	TEEC_Operation op = {0};
	uint32_t ret_orig;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;
	op.params[0].value.b = need_buffering;

	op.params[1].tmpref.buffer = (void *)src;
	op.params[1].tmpref.size = src_len;

	op.params[2].tmpref.buffer = (void *)dst;
	op.params[2].tmpref.size = *dst_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(&KM_session, OTZ_KEYMASTER_CMD_ID_AE_UPDATE, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		LOG_D("Invoke OTZ_KEYMASTER_CMD_ID_AE_UPDATE failed with res(%x), ret_orig(%x)\n", res, ret_orig);
	}

	if (res == TEEC_SUCCESS)
		*dst_len = op.params[2].tmpref.size;

	return res;
}

TEEC_Result tee_ae_encrypt_final(const TEE_OperationHandle oph,
                                 const void *src,
                                 size_t src_len, void *dst,
                                 size_t *dst_len, void *tag,
                                 size_t *tag_len)
{
	TEEC_Result res;
	TEEC_Operation op = {0};
	uint32_t ret_orig;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = (void *)src;
	op.params[1].tmpref.size = src_len;

	op.params[2].tmpref.buffer = (void *)dst;
	op.params[2].tmpref.size = *dst_len;

	op.params[3].tmpref.buffer = (void *)tag;
	op.params[3].tmpref.size = *tag_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_OUTPUT);

	res = TEEC_InvokeCommand(&KM_session, OTZ_KEYMASTER_CMD_ID_AE_ENCRYPT_FINAL, &op,
				 &ret_orig);

	if (res != TEEC_SUCCESS) {
		LOG_D("Invoke OTZ_KEYMASTER_CMD_ID_AE_ENCRYPT_FINAL failed with res(%x), ret_orig(%x)\n", res, ret_orig);
	}

	if (res == TEEC_SUCCESS) {
		*dst_len = op.params[2].tmpref.size;
		*tag_len = op.params[3].tmpref.size;
	}

	return res;
}

TEEC_Result tee_ae_decrypt_final(const TEE_OperationHandle oph,
                                    const void *src, size_t src_len,
                                    void *dst, size_t *dst_len,
                                    const void *tag, size_t tag_len)
{
	TEEC_Result res;
	TEEC_Operation op = {0};
	uint32_t ret_orig;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = (void *)src;
	op.params[1].tmpref.size = src_len;

	op.params[2].tmpref.buffer = dst;
	op.params[2].tmpref.size = *dst_len;

	op.params[3].tmpref.buffer = (void *)tag;
	op.params[3].tmpref.size = tag_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_INPUT);

	res = TEEC_InvokeCommand(&KM_session, OTZ_KEYMASTER_CMD_ID_AE_DECRYPT_FINAL, &op,
				 &ret_orig);

	if (res != TEEC_SUCCESS) {
		LOG_D("Invoke OTZ_KEYMASTER_CMD_ID_AE_DECRYPT_FINAL failed with res(%x), ret_orig(%x)\n", res, ret_orig);
	}

	if (res == TEEC_SUCCESS)
		*dst_len = op.params[2].tmpref.size;

	return res;
}

