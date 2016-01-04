/*
 * Copyright (c) 2015-2016 Amlogic, Inc.
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions and derivatives of the Software.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification is strictly prohibited without prior written consent from
 * Amlogic, Inc.
 *
 * Redistribution in binary form must reproduce the above copyright  notice,
 * this list of conditions and  the following disclaimer in the documentation
 * and/or other materials  provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#ifndef _OTZ_ID_KEYMASTER_H_
#define _OTZ_ID_KEYMASTER_H_

/**
 * @brief KEYMASTER service UUID
 */
/*#define OTZ_SVC_KEYMASTER 0x17*/


/* This UUID is generated with uuidgen
   the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html */
#define KEYMASTER_UUID {0x27768e80, 0x717d, 0x11e5, \
		{ 0xb4, 0xb0, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b} }
/**
 * @brief Enums used for echo service task
 */
enum otz_keymaster_cmd_id {
	OTZ_KEYMASTER_CMD_ID_INIT                   = (0x00),
	OTZ_KEYMASTER_CMD_ID_TERM                   = (0x01),
	OTZ_KEYMASTER_CMD_ID_GENERATE_KEYPAIR       = (0x02),
	OTZ_KEYMASTER_CMD_ID_GET_KEYPAIR_PUBLIC     = (0x03),
	OTZ_KEYMASTER_CMD_ID_IMPORT_KEYPAIR         = (0x04),
	OTZ_KEYMASTER_CMD_ID_QUERY_KEY_EXISTENCE    = (0x05),
	OTZ_KEYMASTER_CMD_ID_SIGN_DIGEST            = (0x06),
	OTZ_KEYMASTER_CMD_ID_VERIFY_SIGNATURE       = (0x07),
	OTZ_KEYMASTER_CMD_ID_DELETE_KEYPAIR         = (0x08),
	OTZ_KEYMASTER_CMD_ID_ALLOCATE_TRANSIENT_OBJ	= (0x09),
	OTZ_KEYMASTER_CMD_ID_FREE_TRANSIENT_OBJ     = (0x0a),
	OTZ_KEYMASTER_CMD_ID_ALLOCATE_OPERATION     = (0x0b),
	OTZ_KEYMASTER_CMD_ID_FREE_OPERATION         = (0x0c),
	OTZ_KEYMASTER_CMD_ID_DIGEST_DO_FINAL        = (0x0d),
	OTZ_KEYMASTER_CMD_ID_SET_OPERATION_KEY      = (0x0e),
	OTZ_KEYMASTER_CMD_ID_POPULATE_TRANSIENT_OBJ	= (0x0f),
	OTZ_KEYMASTER_CMD_ID_GET_OBJ_BUF_ATTR       = (0x10),
	OTZ_KEYMASTER_CMD_ID_GET_OBJ_VALUE_ATTR     = (0x11),
	OTZ_KEYMASTER_CMD_ID_DIGEST_UPDATE          = (0x12),
	OTZ_KEYMASTER_CMD_ID_ASYMMETRIC_EN_DE_CRYPT	= (0x13),
	OTZ_KEYMASTER_CMD_ID_CIPHER_INIT            = (0x14),
	OTZ_KEYMASTER_CMD_ID_CIPHER_UPDATE          = (0x15),
	OTZ_KEYMASTER_CMD_ID_CIPHER_DO_FINAL        = (0x16),
    OTZ_KEYMASTER_CMD_ID_AE_INIT                = (0x17),
    OTZ_KEYMASTER_CMD_ID_AE_UPDATE_AAD          = (0x18),
    OTZ_KEYMASTER_CMD_ID_AE_UPDATE              = (0x19),
    OTZ_KEYMASTER_CMD_ID_AE_ENCRYPT_FINAL       = (0x1a),
    OTZ_KEYMASTER_CMD_ID_AE_DECRYPT_FINAL       = (0x1b),
	OTZ_KEYMASTER_CMD_ID_MAC_INIT               = (0x1c),
	OTZ_KEYMASTER_CMD_ID_MAC_UPDATE             = (0x1d),
	OTZ_KEYMASTER_CMD_ID_MAC_DO_FINAL           = (0x1e),
	OTZ_KEYMASTER_CMD_ID_MAC_DO_FINAL_COMPARE   = (0x1f),
	OTZ_KEYMASTER_CMD_ID_IMPORT_SYMMETRIC_KEY   = (0x20),
	OTZ_KEYMASTER_CMD_ID_LOAD_KEY               = (0x21),
	OTZ_KEYMASTER_CMD_ID_MAC_KEYBLOB_INIT       = (0x22),
	OTZ_KEYMASTER_CMD_ID_UNKNOWN                = (0x7FFFFFFE),
	OTZ_KEYMASTER_CMD_ID_MAX                    = (0x7FFFFFFF)
};

#endif
