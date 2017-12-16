# Copyright (C) 2009 The Android Open Source Project
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
#
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

#SYSROOT=/home/moslab/android_tool/android-ndk-r10e/platforms/android-19/arch-arm
LOCAL_MODULE    := libonedrive_hook
LOCAL_SRC_FILES := urlmon_arm.c.arm urlmon.c helper.c helpfnc.c jsmn.c state.c
LOCAL_C_INCLUDES := ../../../adbi/instruments/base/ ../../../dalvikhook/jni/
LOCAL_LDLIBS    :=  -ldl -lz -Wl,--start-group ../../../adbi/instruments/base/obj/local/armeabi/libbase.a ../../../dalvikhook/obj/local/armeabi/libdalvikhook.a -Wl,--end-group
# LOCAL_STATIC_LIBRARY   :=  -ldl -lz -Wl,--start-group ../../../adbi/instruments/base/obj/local/armeabi/libbase.a ../../../dalvikhook/obj/local/armeabi/libdalvikhook.a -Wl,--end-group
LOCAL_CFLAGS    := -g

include $(BUILD_SHARED_LIBRARY)
