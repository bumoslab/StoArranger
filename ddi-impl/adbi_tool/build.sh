#!/bin/bash
shopt -s expand_aliases

# set PATH_TONDK, please use android-ndk-r10e to build
if [ -z "$PATH_TO_NDK" ]
then
    echo "error: Can not find ndk"
    echo "error: Please set PATH_TO_NDK, and use android-ndk-r10e to build"
    exit;
fi
# set PATH_TONDK, please use android-ndk-r10e to build
alias ndk-build="$PATH_TO_NDK/ndk-build"
cd hijack/jni
ndk-build
cd ../..

cd instruments
cd base/jni
ndk-build
cd ../..

cd example/jni
ndk-build
cd ../..

cd ..

