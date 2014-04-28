/*
 * Copyright (c) 2010-2013 Sierraware, LLC.
 *
 * The above copyright notice and this permission notice shall be included in 
 * all copies or substantial portions and derivatives of the Software.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification is strictly prohibited without prior written consent from
 * Sierraware, LLC.
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
#define OTZ_SVC_KEYMASTER 0x17

/**
 * @brief Enums used for echo service task
 */
enum otz_keymaster_cmd_id {
    OTZ_KEYMASTER_CMD_ID_INVALID        = 0x0,
    OTZ_KEYMASTER_CMD_ID_INIT,
    OTZ_KEYMASTER_CMD_ID_TERM,
    OTZ_KEYMASTER_CMD_ID_GENERATE_KEYPAIR,
    OTZ_KEYMASTER_CMD_ID_GET_KEYPAIR_PUBLIC,
    OTZ_KEYMASTER_CMD_ID_IMPORT_KEYPAIR,
    OTZ_KEYMASTER_CMD_ID_GET_KEY_TYPE,
    OTZ_KEYMASTER_CMD_ID_SIGN_DATA,
    OTZ_KEYMASTER_CMD_ID_VERIFY_DATA,
    OTZ_KEYMASTER_CMD_ID_DELETE_KEYPAIR,
    OTZ_KEYMASTER_CMD_ID_UNKNOWN        = 0x7FFFFFFE,
    OTZ_KEYMASTER_CMD_ID_MAX            = 0x7FFFFFFF
};

#endif
