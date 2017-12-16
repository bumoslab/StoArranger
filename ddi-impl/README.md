Hook onedrive app
=========================================================

use adbi tool to hook onedrive application on android 4.4

=== Prerequisites ===

Android SDK
Android NDK
You'd better to use android-ndk-r10e to build the proejct

=== How to Build ===
To build adbi tool, please refer to the documents of adbi project below
https://github.com/crmulliner/adbi

= build stoarrage project=

Assume you have made adbi binary ready
set variable PATH_TO_NDK to the path of NKD, then run
~~~~bash
./build.sh
~~~~

push hijack and library to android device

~~~bash
cd adbi/hijack
adb push libs/armeabi/hijack /data/local/tmp/
cd ../../example/onedrive_hook
adb push ../libs/armeabi/liburl.so /data/local/tmp
~~~~


=== How to Run ===

~~~~bash
adb shell
su
cd /data/local/tmp
>/data/local/tmp/onedrive-hook.log
~~~~

GET PID from com.android.phone

~~~~bash
./hijack -d -p PID -l /data/local/tmp/libexample.so
cat onedrive-hook.log
~~~

