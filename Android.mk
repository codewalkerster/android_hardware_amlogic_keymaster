# Copyright (C) 2012 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := keystore.amlogic
LOCAL_MODULE_PATH := $(TARGET_OUT_SHARED_LIBRARIES)/hw
LOCAL_SRC_FILES := module.cpp
LOCAL_C_INCLUDES := \
	libnativehelper/include/nativehelper/\
	system/security/keystore \
	external/openssl/include 

LOCAL_CFLAGS = -fvisibility=hidden -Wall -Werror
ifeq ($(TARGET_USE_SECUREOS),true)
LOCAL_CFLAGS += -DUSE_SECUREOS
endif
LOCAL_SHARED_LIBRARIES := libcrypto liblog libkeystore_binder libamlkeymaster 
LOCAL_MODULE_TAGS := optional
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libamlkeymaster
LOCAL_SRC_FILES := keymaster_aml.cpp
LOCAL_C_INCLUDES := \
	libnativehelper/include/nativehelper/\
	system/security/keystore \
	external/openssl/include \
	$(LOCAL_PATH)/include \
	hardware/amlogic/keymaster/secure-os \
	system/security/softkeymaster/include

LOCAL_CFLAGS = -fvisibility=hidden -Wall -Werror

LOCAL_SHARED_LIBRARIES := libcrypto liblog libkeystore_binder libsoftkeymaster

ifeq ($(TARGET_USE_SECUREOS),true)
#LOCAL_C_INCLUDES += vendor/amlogic/bdk/include
LOCAL_SHARED_LIBRARIES += libotzapi
LOCAL_STATIC_LIBRARIES := libamlkeymaster_api
LOCAL_REQUIRED_MODULES := keymaster
LOCAL_CFLAGS += -DUSE_SECUREOS
endif

LOCAL_MODULE_TAGS := optional
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
include $(BUILD_SHARED_LIBRARY)

ifeq ($(TARGET_USE_SECUREOS),true)
#include $(CLEAR_VARS)
#LOCAL_MODULE := libamlkeymaster_api
#LOCAL_CFLAGS := -DANDROID_BUILD
#
#LOCAL_C_INCLUDES := \
#	vendor/amlogic/bdk/include
#
#LOCAL_SHARED_LIBRARIES := \
#	libotzapi
#
#LOCAL_SHARED_LIBRARIES += libcutils liblog
#LOCAL_SRC_FILES := secure-os/keymaster_secure_api.c
#LOCAL_MODULE_TAGS := optional
#include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_PREBUILT_LIBS := secure-os/libamlkeymaster_api.a
include $(BUILD_MULTI_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := keymaster
LOCAL_MODULE_CLASS := SHARED_LIBRARIES
LOCAL_MODULE_SUFFIX := .tzo
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_PATH := $(TARGET_OUT_SHARED_LIBRARIES)
LOCAL_SRC_FILES := secure-os/$(LOCAL_MODULE)$(LOCAL_MODULE_SUFFIX)
include $(BUILD_PREBUILT)

endif
