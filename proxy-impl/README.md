
# OVERVIEW #
Our implementation of proxy is based on sslplit, please refer to [here](https://github.com/droe/sslsplit.git) for more details

# How to compile binary for android 4.4: #

1. Modify the GNUMakefie: Set NDK variable to the path of NDK.
~~~~ bash
    make
~~~~

# How to run sslsplit on android #

1. push sslplit to android device
```
    adb push sslsplit /
```

2. generate ca.key and ca.crt in ubuntu
```
    openssl genrsa -out ca.key 4096
    openssl req -new -x509 -days 1826 -key ca.key -out ca.crt
    adb push ca.key /
    adb push ca.crt /
```

3. Install ca.crt into the phone

4. Run sslplit on android, need root privilege
```
    adb shell
    ./sslsplit -k ca.key -c ca.crt ssl 0.0.0.0 8888
```

    NOTE: 0.0.0.0 can be set to the ip address of the sslsplit.
    8888 is the port of proxy setting.
    using -D to enable Debug mode, which would print more information.
