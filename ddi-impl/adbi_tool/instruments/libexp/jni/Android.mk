LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := base
LOCAL_SRC_FILES := ../../base/obj/local/armeabi/libbase.a
LOCAL_EXPORT_C_INCLUDES := ../../base
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libmyinflate
LOCAL_SRC_FILES := ../my_inflate.c ../my_inflate_arm.c.arm
LOCAL_CLAGS := -g
LOCAL_SHARED_LIBRARIES := dl
LOCAL_STATIC_LIBRARIES := base
include $(BUILD_SHARED_LIBRARY)
