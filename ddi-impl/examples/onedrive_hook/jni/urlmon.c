/*
 *  Collin's Dynamic Dalvik Instrumentation Toolkit for Android
 *  Collin Mulliner <collin[at]mulliner.org>
 *
 *  (c) 2012,2013
 *
 *  License: LGPL v2.1
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <string.h>
#include <termios.h>
#include <pthread.h>
#include <sys/epoll.h>

#include <jni.h>
#include <stdlib.h>
#include <sys/timeb.h>


#include "hook.h"
#include "dexstuff.h"
#include "dalvik_hook.h"
#include "base.h"
#include "helper.h"

#define OPENSSL_HOOK

enum edge_response {
	EDGE_FAILED = 0,
	EDGE_PROCCESS_AS_NORMAL,
	EDGE_SUCCEED
};

/* edge project onedriveclient response */
char* onedrivev1_upload_response =
"HTTP/1.1 200 OK\r\n"
"Content-Length: 4\r\n"
"Content-Type: application/json; odata.metadata=minimal; odata.streaming=true\r\n"
"ETag: aNDJBNjM4QzU5QUExRUFBOCE3MjYwLjI3OQ\r\n"
"Server: Microsoft-IIS/8.5\r\n"
"P3P: CP=\"BUS CUR CONo FIN IVDo ONL OUR PHY SAMo TELo\"\r\n"
"X-MSNSERVER: BN2BAP57FD2F9AB\r\n"
"Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n"
"X-Resource-Id: 42A638C59AA1EAA8!7260\r\n"
"X-Cid: 4802588473991228072\r\n"
"X-Last-Modified-ISO8601: 2017-04-12T19:03:39.613Z\r\n"
"X-ItemVersion: 279\r\n"
"OData-Version: 4.0\r\n"
"X-AsmVersion: UNKNOWN; 22.1.0.0\r\n"
"X-MSEdge-Ref: Ref A: 533562FB06CA439DAEDF0281B1574124 Ref B: CH1EDGE0113 Ref C: Wed Apr 12 12:03:40 2017 PST\r\n"
"Date: Wed, 12 Apr 2017 19:03:39 GMT\r\n\r\n"
"{\n}\n";

#define EDGE_PORT 8001
#define RECV_BUFF 100

static struct hook_t eph;
static struct dexstuff_t d;

static int debug;

extern struct state* delta_stat;
static pthread_mutex_t glock;
static void my_log(char *msg)
{
	log("%s", msg)
}
static void my_log2(char *msg)
{
	if (debug)
		log("%s", msg)
}

static struct dalvik_hook_t sb1;
static struct dalvik_hook_t sb2;
static struct dalvik_hook_t sb3;
static struct dalvik_hook_t sb4;
static struct dalvik_hook_t sb5;
static struct dalvik_hook_t sb6;
static struct dalvik_hook_t sb7;
static struct dalvik_hook_t sb8;
static struct dalvik_hook_t sb9;
static struct dalvik_hook_t sb10;
static struct dalvik_hook_t sb11;
static struct dalvik_hook_t sb13;
static struct dalvik_hook_t sb14;
static struct dalvik_hook_t sb20;


extern struct DvmGlobals gDvm;


static void* mycallObjectMethod(JNIEnv* env, jobject obj, const char* methodName, const char* sig);
static void* mycallObjectMethodA(JNIEnv* env, jobject obj, const char* methodName, const char* sig, jvalue* args);
static jint mycallIntMethod(JNIEnv* env, jobject obj, const char* methodName, const char* sig);
static jint mycallIntMethodA(JNIEnv* env, jobject obj, const char* methodName, const char* sig, jvalue* args);
static jboolean mycallBooleanMethod(JNIEnv* env, jobject obj, const char* methodName, const char* sig);
static void mycallVoidMethod(JNIEnv* env, jobject obj, const char* methodName, const char* sig);
static void mycallVoidMethodA(JNIEnv* env, jobject obj, const char* methodName, const char* sig, jvalue* args);

static jobject getObjectFieldValue(JNIEnv* env, jobject obj,const char* fieldName,const char* sig);
static jboolean getBooleanFieldValue(JNIEnv* env, jobject obj,const char* fieldName,const char* sig);
static jlong getLongFieldValue(JNIEnv* env, jobject obj,const char* fieldName,const char* sig);
static jlong getIntFieldValue(JNIEnv* env, jobject obj,const char* fieldName,const char* sig);

static void log_jstring(JNIEnv* env, const char* format,jstring str);

 void sb3_setMethod(JNIEnv* env, jobject obj, jobject str){

     log("hook setMethod: %s\n",sb3.clnamep);

     jvalue args[1];
     args[0].l = str;
     dalvik_prepare(&d,&sb3,env);
     (*env)->CallObjectMethodA(env,obj,sb3.mid,args);
     dalvik_postcall(&d,&sb3);
     return ;

 }
 void* sb4_getResponseCode(JNIEnv* env, jobject obj){

     log("hook sb4_getResponseCode: %s\n",sb4.clnamep);

     dalvik_prepare(&d,&sb4,env);
     int res = (*env)->CallIntMethod(env,obj,sb4.mid);
     dalvik_postcall(&d,&sb4);
     return  (void*)res;

 }

/*
 * void sb1_sendRequest(JNIEnv* env, jobject obj)
 * {
 *     log("hook sendRequest\n");
 *
 *     [> get clazz <]
 *     jclass cls = (*env)->GetObjectClass(env,obj);
 *     //get field value
 *     log("\n");
 *     jfieldID strmetid = (*env)->GetFieldID(env,cls,"method","Ljava/lang/String;");
 *     log("sendRequest get GetFieldID %d\n",(unsigned int)strmetid);
 *     jstring mvalue = (*env)->GetObjectField(env,obj, strmetid);
 *     log("sendRequest get GetObjectField\n");
 *
 *     const char* value = (*env)->GetStringUTFChars(env,mvalue,NULL);
 *     log("method in Engine %s\n",value);
 *     (*env)->ReleaseStringUTFChars(env,mvalue,value);
 *
 *     [> get URI <]
 *     {
 *         jobject uri_obj = getObjectFieldValue(env,obj,"uri","Ljava/net/URI;");
 *
 *         jstring host = mycallObjectMethod(env, uri_obj,"getHost","()Ljava/lang/String;");
 *         log_jstring(env,"host name %s\n",host);
 *
 *     }
 *
 *     {
 *         jobject requestHeader = getObjectFieldValue(env,obj,"requestHeaders","Lcom/android/okhttp/internal/http/RequestHeaders;");
 *
 *         log("requestHeaders\n");
 *         jobject headersToSend = getObjectFieldValue(env,requestHeader,"headers","Lcom/android/okhttp/internal/http/RawHeaders;");
 *
 *         log("HeadersToSend\n");
 *         jbyteArray bytes = mycallObjectMethod(env,headersToSend,"toBytes","()[B");
 *         log("jbyteArray\n");
 *
 *         int len = (*env)->GetArrayLength(env,bytes);
 *         char* buf = malloc(len);
 *         (*env)->GetByteArrayRegion(env,bytes, 0, len,buf);
 *         log("header %s\n",buf);
 *
 *     }
 *
 *     dalvik_prepare(&d,&sb1,env);
 *     (*env)->CallObjectMethod(env,obj,sb1.mid);
 *     dalvik_postcall(&d,&sb1);
 *
 *     jmethodID getRequestLine_id = (*env)->GetMethodID(env,cls,"getRequestLine","()Ljava/lang/String;");
 *     jstring request_str = (*env)->CallObjectMethod(env,obj,getRequestLine_id);
 *     const char* request_chars = (*env)->GetStringUTFChars(env, request_str,NULL);
 *     log("getRequestLine in Engine %s\n",request_chars);
 *     (*env)->ReleaseStringUTFChars(env,request_str,request_chars);
 *
 *     return;
 *
 * } */

 void sb7_onMAMReceive(JNIEnv* env, jobject obj, jobject context, jobject intent)
 {
     jvalue args[2];
     args[0].l = context;
     args[1].l = intent;
     log("New Picture Hook\n");

     jstring str_uri =  mycallObjectMethod(env,intent,"getDataString","()Ljava/lang/String;");
     log_jstring(env,"New Picture upload uri %s\n",str_uri);

     jstring str_path =  mycallObjectMethod(env,intent,"getDataString","()Ljava/lang/String;");
     log_jstring(env,"New Picture upload uri %s\n",str_path);

     dalvik_prepare(&d,&sb7,env);
     (*env)->CallObjectMethodA(env,obj,sb7.mid,args);
     dalvik_postcall(&d,&sb7);
 }

 jobject mFoleder_getAsString(JNIEnv* env, jobject obj,const char* method, const char* sig,const char* key) { jstring jkey = (*env)->NewStringUTF(env,key);
     jvalue args[1];
     args[0].l = jkey;

     jclass cls = (*env)->GetObjectClass(env,obj);
     jmethodID mid = (*env)->GetMethodID(env, cls, method, sig);
     return (*env)->CallObjectMethodA(env,obj,mid,args);
 }

 void sb6_onActivityResult(JNIEnv *env, jobject obj, jint requestCode, jint resultCode,jobject data)
 {
     log("\n");
     log("hook sb6_onActivityResult\n");
     jvalue args[3];
     args[0].i = requestCode;
     if(resultCode ==  -1)
         args[1].i = 0;
 //    args[1].i = resultCode;
     args[2].l = data;

     log("requestCode: %d resultCode %d\n",requestCode, resultCode);

     {
         jobject thiz_intent = mycallObjectMethod(env, obj,"getIntent","()Landroid/content/Intent;");
         log("n1\n");
         jobject obj_uploadRequestProcessor = mycallObjectMethod(env,thiz_intent,"getExtras","()Landroid/os/Bundle;");
         log("n2\n");
         char * key = "filePickerDelegateKey";
         jstring jkey = (*env)->NewStringUTF(env,key);
         jvalue args[1];
         args[0].l = jkey;

         log("n3\n");
         jobject obj_devicepicker = mycallObjectMethodA(env,obj_uploadRequestProcessor,"getParcelable","(Ljava/lang/String;)Landroid/os/Parcelable;",args);

         log("n4\n");
         jobject obj_mFolder = getObjectFieldValue(env, obj_devicepicker,"mFolder","Landroid/content/ContentValues;");
         log("n5\n");

         jobject jown_id = mFoleder_getAsString(env,obj_mFolder,"getAsString","(Ljava/lang/String;)Ljava/lang/String;","ownid");
         log_jstring(env,"own_id %s\n",jown_id);

         jobject jresourcePartitionCid = mFoleder_getAsString(env,obj_mFolder,"getAsString","(Ljava/lang/String;)Ljava/lang/String;","resourcePartitionCid");
         log_jstring(env,"resourcePartitionCid %s\n",jresourcePartitionCid);

         jobject jresourceId = mFoleder_getAsString(env,obj_mFolder,"getAsString","(Ljava/lang/String;)Ljava/lang/String;","resourceId");
         log_jstring(env,"resourceId %s\n",jresourceId);

         jobject jaccountId = mFoleder_getAsString(env,obj_mFolder,"getAsString","(Ljava/lang/String;)Ljava/lang/String;","accountId");
         log_jstring(env,"accountId %s\n",jaccountId);

     }



     if(resultCode == -1){
         jstring str_uri =  mycallObjectMethod(env,data,"getDataString","()Ljava/lang/String;");
         log_jstring(env,"upload uri %s\n",str_uri);
     }
     dalvik_prepare(&d,&sb6,env);
     (*env)->CallObjectMethodA(env,obj,sb6.mid,args);
     dalvik_postcall(&d,&sb6);
     log("\n");
 }

 void sb5_startActivityForResult(JNIEnv *env, jobject obj, jobject Intent, jint op,jobject options)
 {
     log("hook sb5_startActivityForResult\n");
     jvalue args[3];
     args[0].l = Intent;
     args[1].i = op;
     args[2].l = options;

     //get class Name of this obj <]
     jobject clsobj = mycallObjectMethod(env,obj,"getClass","()Ljava/lang/Class;");
     jstring jstr_name = mycallObjectMethod(env,clsobj,"getName","()Ljava/lang/String;");
     log_jstring(env,"StartActivityForResult Class Name: %s\n", jstr_name); //com.microsoft.skydrive.upload.picker.SAFPickerActivity

     // get Action Name  <]
     jstring jstr_action = mycallObjectMethod(env,Intent,"getAction","()Ljava/lang/String;");
     log_jstring(env,"Intent Action: %s\n",jstr_action); //android.intent.action.OPEN_DOCUMENT

     dalvik_prepare(&d,&sb5,env);
     (*env)->CallObjectMethodA(env,obj,sb5.mid,args);
     dalvik_postcall(&d,&sb5);
 }

 void sb4_startActivityForResult(JNIEnv *env, jobject obj, jobject Intent, jint op)
 {
     log("hook sb4_startActivityForResult\n");
     jvalue args[2];
     args[0].l = Intent;
     args[0].i = op;
     dalvik_prepare(&d,&sb4,env);
     (*env)->CallObjectMethodA(env,obj,sb4.mid,args);
     dalvik_postcall(&d,&sb4);
 }


double time_milli()
{
	struct timeb tmb;
	ftime(&tmb);
	return (double)tmb.time + (double)tmb.millitm / 1000;
}

static jboolean getBooleanFieldValue(JNIEnv* env, jobject obj,const char* fieldName,const char* sig)
{
    jclass cls = (*env)->GetObjectClass(env, obj);
    jfieldID fid = (*env)->GetFieldID(env,cls,fieldName,sig);
    return (*env)->GetBooleanField(env,obj,fid);
}

static jlong getLongFieldValue(JNIEnv* env, jobject obj,const char* fieldName,const char* sig)
{
    jclass cls = (*env)->GetObjectClass(env, obj);
    jfieldID fid = (*env)->GetFieldID(env,cls,fieldName,sig);
    if(fid != NULL)
        return (*env)->GetLongField(env,obj,fid);
    else
        return -1;
}
static jlong getIntFieldValue(JNIEnv* env, jobject obj,const char* fieldName,const char* sig)
{
    jclass cls = (*env)->GetObjectClass(env, obj);
    jfieldID fid = (*env)->GetFieldID(env,cls,fieldName,sig);
    if(fid != NULL)
        return (*env)->GetIntField(env,obj,fid);
    else
        return -1;
}

static jobject getObjectFieldValue(JNIEnv* env, jobject obj,const char* fieldName,const char* sig)
{
    jclass cls = (*env)->GetObjectClass(env, obj);
    jfieldID fid = (*env)->GetFieldID(env,cls,fieldName,sig);
    if(fid != NULL)
        return (*env)->GetObjectField(env,obj,fid);
    else
        return NULL;
}

static void log_jstring(JNIEnv* env, const char* format,jstring str)
{
   const char* s = (*env)->GetStringUTFChars(env,str,NULL);
   if(s){
       log(format,s);
       (*env)->ReleaseStringUTFChars(env,str,s);
   }else {
       log("hostname is null\n");
   }
}

static void* mycallObjectMethod(JNIEnv* env, jobject obj, const char* methodName, const char* sig)
{
    jclass cls = (*env)->GetObjectClass(env,obj);
    jmethodID mid = (*env)->GetMethodID(env, cls, methodName, sig);
    return (*env)->CallObjectMethod(env,obj,mid);
}

static void* mycallObjectMethodA(JNIEnv* env, jobject obj, const char* methodName, const char* sig, jvalue* args)
{
    jclass cls = (*env)->GetObjectClass(env,obj);
    jmethodID mid = (*env)->GetMethodID(env, cls, methodName, sig);
    return (*env)->CallObjectMethodA(env,obj,mid,args);
}

static jint mycallIntMethod(JNIEnv* env, jobject obj, const char* methodName, const char* sig)
{
    jclass cls = (*env)->GetObjectClass(env,obj);
    jmethodID mid = (*env)->GetMethodID(env, cls, methodName, sig);
    return (*env)->CallIntMethod(env,obj,mid);
}

static jint mycallIntMethodA(JNIEnv* env, jobject obj, const char* methodName, const char* sig, jvalue* args)
{
    jclass cls = (*env)->GetObjectClass(env,obj);
    jmethodID mid = (*env)->GetMethodID(env, cls, methodName, sig);
    return (*env)->CallIntMethodA(env,obj,mid,args);
}

static jboolean mycallBooleanMethod(JNIEnv* env, jobject obj, const char* methodName, const char* sig)
{
    jclass cls = (*env)->GetObjectClass(env,obj);
    jmethodID mid = (*env)->GetMethodID(env, cls, methodName, sig);
    return (*env)->CallBooleanMethod(env,obj,mid);
}

static void mycallVoidMethod(JNIEnv* env, jobject obj, const char* methodName, const char* sig)
{
    jclass cls = (*env)->GetObjectClass(env,obj);
    jmethodID mid = (*env)->GetMethodID(env, cls, methodName, sig);
    (*env)->CallVoidMethod(env,obj,mid);
    return;
}

static void mycallVoidMethodA(JNIEnv* env, jobject obj, const char* methodName, const char* sig, jvalue* args)
{
    jclass cls = (*env)->GetObjectClass(env,obj);
    jmethodID mid = (*env)->GetMethodID(env, cls, methodName, sig);
    (*env)->CallVoidMethodA(env,obj,mid,args);
    return;
}


void* sb2_inputread3(JNIEnv* env, jobject obj, jbyteArray array,jint off,jint len)
{

    jvalue args[3];
    args[0].l = array;
    args[1].j = off;
    args[2].j = len;

    log("===> BufferedInputStream read  hooked \n");
    /* jobject out = getObjectFieldValue(env,obj,"in","Ljava/io/InputStream;"); */

    /* jobject clsobj = mycallObjectMethod(env,out,"getClass","()Ljava/lang/Class;"); */
    /* jstring jstr_name = mycallObjectMethod(env,clsobj,"getName","()Ljava/lang/String;"); */
    /* log_jstring(env,"input Class Name: %s\n", jstr_name); //com.microsoft.skydrive.upload.picker.SAFPickerActivity */

    dalvik_prepare(&d,&sb2,env);
    log("=>Call Orignial Method\n");
    int res = (*env)->CallIntMethodA (env,obj,sb2.mid,args);
    dalvik_postcall(&d,&sb2);
    return (void *)res;
}
//httpsclient app
void* sb6_inputread(JNIEnv* env, jobject obj, jbyteArray array)
{
    /* */
//    log("sb6_inputread ======================================\n");
    int length = (*env)->GetArrayLength(env,array);
    jvalue args[3];
    args[0].l = array;
    args[1].j = 0;
    args[2].j = length;

//    dalvik_prepare(&d,&sb6,env);
//    log("orgin %d h->insns %d \n",(unsigned int)sb6.orign_method->insns,(unsigned int)sb6.insns);

    int res = mycallIntMethodA(env,obj, "read","([BII)I",args);
//    int res = (*env)->CallIntMethodA(env,obj,sb6.mid,args);
//    dalvik_postcall(&d,&sb6);
//    int res = mycallIntMethodA(env,obj,"read","([BII)I",args);

    char* buf = malloc(length + 1);
    memset(buf,'\0',length + 1);
    (*env)->GetByteArrayRegion(env, array, 0, length, buf);

//    log("sb6 input buffer len %d res %d %s : \n", length,res, buf);
    free(buf);
    return (void*)res;

}

void sb2_outputwrite(JNIEnv* env, jobject obj, jbyteArray array)
{
    jvalue args[1];
    args[0].l = array;

#if 0
    /* get class name */
    {
       jobject clsobj = mycallObjectMethod(env,obj,"getClass","()Ljava/lang/Class;");
       jstring jstr_name = mycallObjectMethod(env,clsobj,"getName","()Ljava/lang/String;");
//       log_jstring(env,"outputwrite Class Name: %s\n", jstr_name); //com.microsoft.skydrive.upload.picker.SAFPickerActivity

    }
    {
        jobject field_obj = getObjectFieldValue(env,obj,"out","Ljava/io/OutputStream;");
        if(field_obj != NULL){
            jobject clsobj = mycallObjectMethod(env,field_obj,"getClass","()Ljava/lang/Class;");
            jstring jstr_name = mycallObjectMethod(env,clsobj,"getName","()Ljava/lang/String;");
            log_jstring(env,"field output Class Name: %s\n", jstr_name); //com.microsoft.skydrive.upload.picker.SAFPickerActivity
        }else{
            log("No field named out\n");
        }
    }

    int len = (*env)->GetArrayLength(env,array);
    char* buf = malloc(len + 1);
    memset(buf,'\0',len + 1);
    (*env)->GetByteArrayRegion(env, array, 0, len,buf);
    int i = 0;
    log("output array %d \n", len);
    /* for(;i < len; ++i){
     *     log("%d", buf[i]);
     * }
     * log("\n"); */
    log("%s",buf);
#endif
    log("sb2_outputWrite\n");
    int len = (*env)->GetArrayLength(env,array);
    char* buf = malloc(len + 1);
    memset(buf,'\0',len + 1);
    (*env)->GetByteArrayRegion(env, array, 0, len,buf);
    log("output array %d \n", len);

    dalvik_prepare(&d,&sb2,env);
    (*env)->CallObjectMethodA(env,obj,sb2.mid,args);
    dalvik_postcall(&d,&sb2);

}

void sb1_outputwrite3(JNIEnv* env, jobject obj, jbyteArray array,jint off,jint len)
{

    jvalue args[3];
    args[0].l = array;
    args[1].j = off;
    args[2].j = len;

    log("===> DataOutputStream write  hooked \n");
/*     jobject out = getObjectFieldValue(env,obj,"out","Ljava/io/OutputStream;");
 *
 *     jobject clsobj = mycallObjectMethod(env,out,"getClass","()Ljava/lang/Class;");
 *     jstring jstr_name = mycallObjectMethod(env,clsobj,"getName","()Ljava/lang/String;");
 *     log_jstring(env,"output Class Name: %s\n", jstr_name); //com.microsoft.skydrive.upload.picker.SAFPickerActivity */

    dalvik_prepare(&d,&sb1,env);
    log("=>Call Orignial Method\n");
    (*env)->CallObjectMethodA(env,obj,sb1.mid,args);
    dalvik_postcall(&d,&sb1);
}

void sb3_outputwrite_trace(JNIEnv* env, jobject obj, jbyteArray array,jint off,jint len) //time trace
{

    double start_time = time_milli();
    /** log("outputstreamStarttime %0.3f\n",start_time); */
    jvalue args[3];
    args[0].l = array;
    args[1].j = off;
    args[2].j = len;
    dalvik_prepare(&d,&sb3,env);
    /** log("=>Call Orignial Method\n"); */
    (*env)->CallObjectMethodA(env,obj,sb3.mid,args);
    dalvik_postcall(&d,&sb3);
}

void* sb5_inputread_trace(JNIEnv* env, jobject obj, jbyteArray array,jint offset,jint count)//time trace
{


        jobject obj_field = getObjectFieldValue(env, obj,"this$0","Lcom/android/org/conscrypt/OpenSSLSocketImpl;");
        jvalue args[7];

        /* get NativeCrypto class, env->FindClass would cause app crash */
        void *target_cls = d.dvmFindLoadedClass_fnPtr("Lcom/android/org/conscrypt/NativeCrypto;");
        if(target_cls == NULL){
            log("dvmFindLoadedClass: can not find class %s\n","com/android/org/conscrypt/NativeCrypto");
            target_cls = d.dvmFindSystemClass_fnPtr("Lcom/android/org/conscrypt/NativeCrypto;");
        }

        if(target_cls == NULL){
            log("dvmFindSystemClass: can not find class %s\n","com/android/org/conscrypt/NativeCrypto");
            log("dvm\n");
            // target_cls = dex->dvmFindSystemClassNoInit_fnPtr(h->clname);
            log("dvmFindSystemClass: can not find class %s\n","com/android/org/conscrypt/NativeCrypto");
        }

        /* SSL_read method in NativeCrypto Class*/
        Method *crypto_method = d.dvmFindDirectMethodByDescriptor_fnPtr(target_cls,"SSL_read","(JLjava/io/FileDescriptor;Lcom/android/org/conscrypt/NativeCrypto$SSLHandshakeCallbacks;[BIII)I");

        if(crypto_method == NULL){
            log("cant no find method\n");
        }

        long sslpointer = getLongFieldValue(env,obj_field,"sslNativePointer","J");
        jobject obj_socket = getObjectFieldValue(env,obj_field,"socket","Ljava/net/Socket;");
        jobject fd = mycallObjectMethod(env,obj_socket,"getFileDescriptor$","()Ljava/io/FileDescriptor;");
        jint timeout = mycallIntMethod(env,obj_field,"getSoTimeout","()I");
        args[0].j = sslpointer;
        args[1].l = fd;
        args[2].l = obj_field;//opensslsocketimpl
        args[3].l = array;
        args[4].i = offset;
        args[5].i = count;
        args[6].i = timeout;
        jobject read_lock = getObjectFieldValue(env,obj_field,"readLock","Ljava/lang/Object;");
        (*env)->MonitorEnter(env,read_lock);

        /* TODO: implement checkOpen, which is private method
         * mycallVoidMethod(env,obj_field,"checkOpen","()V");
         * log("checkopen\n"); */
        if(count == 0)
            return 0;
        //call method
        int res = (*env)->CallStaticIntMethodA(env,target_cls,(void*)crypto_method,args);
        (*env)->MonitorExit(env,read_lock);
        /* log(" =>Call Orignial Method Finished\n"); */
        double end_time = time_milli();
        /** log("inputstreamEndtime %0.3f\n",end_time); */
        return (void*)res;

}

void sb3_outputwriteA(JNIEnv* env, jobject obj, jbyteArray array,jint off,jint len)//cache
{
    jvalue args[3];
    args[0].l = array;
    args[1].j = off;
    args[2].j = len;

    log("===> SSLOutputStream write  hooked \n");
    double start_time, end_time;
    start_time = time_milli();
    log("OutputStreamStartTime %.5f\n",start_time);
    jobject obj_field = getObjectFieldValue(env, obj,"this$0","Lcom/android/org/conscrypt/OpenSSLSocketImpl;");

    int length = (*env)->GetArrayLength(env,array);
    char* tmp_request_buf = malloc(length + 1);
    memset(tmp_request_buf,'\0',length + 1);
    (*env)->GetByteArrayRegion(env, array, off, len, tmp_request_buf);

//    log(" %s\n",tmp_request_buf);
    int send_metadata = 0;
    const char* hostname;
    jint lc_port;

    if(obj_field != NULL){
        jstring obj_hostname = getObjectFieldValue(env,obj_field,"hostname","Ljava/lang/String;");
        hostname = (*env)->GetStringUTFChars(env,obj_hostname,NULL);
//        log_jstring(env,"this$0-hostname: %s\n",obj_hostname);

        jobject obj_socket = getObjectFieldValue(env,obj_field,"socket","Ljava/net/Socket;");
        jint rm_port = mycallIntMethod(env,obj_socket,"getPort","()I");
        lc_port = mycallIntMethod(env,obj_socket,"getLocalPort","()I");

//        log(" remote port: %d local port: %d\n", rm_port, lc_port);
        int rt = process_request(tmp_request_buf, off,len,hostname,lc_port);
//        log("rt is %d\n",rt);

//        (*env)->ReleaseStringUTFChars(env,obj_hostname,hostname);
        if(rt == 1){
            return;
        }
        if(rt == 2){//send metadata request
            log("call send method\n");
            char* method, *id,*query ,*type;
            parse_request(tmp_request_buf,&method,&id,&query,&type);
            char* start = strstr(tmp_request_buf, "Authorization: bearer ");
            char* end = strstr(start,"\r\n");
            size_t size = end - start - strlen("Authorization: bearer ");
            char* token = malloc(size + 1);
            memset(token,'\0', size + 1);
            memcpy(token, start + strlen("Authorization: bearer "), size);
            /* Generate Get Metadata Request */
            char *request =  generate_md_request(id,token,size);
            int len = strlen(request);
            jbyteArray meta_array = (*env)->NewByteArray (env,len);
            (*env)->SetByteArrayRegion (env,meta_array, 0, len, (jbyte*)(request));
            args[0].l = meta_array;
            args[1].j = 0;
            args[2].j = len;
            send_metadata = 1;
        }else if(rt == 3){ //data
            //send cacheing response back to client
            struct context *ctx = get_context(hostname, lc_port);
            log("rt is 3 cotext %p\n",ctx);
            log("ctx->item_ref not null\n");
            //struct item* tmp = (struct item*)rt;
            return;

        }
    }
//    free(buf);

    /*
     * TODO: convert to native code
     * */
//    log("rt is 5\n");
    dalvik_prepare(&d,&sb3,env);
    log("=>Call Orignial Method\n");
    (*env)->CallObjectMethodA(env,obj,sb3.mid,args);
    dalvik_postcall(&d,&sb3);

    /*
     * proce metadata response if send a metadata request.
     * */
    if(send_metadata){// receive metadata response
        jobject is_obj = getObjectFieldValue(env,obj_field,"is","Ljava/io/InputStream;");
//        log(" object %d\n",(unsigned int)is_obj);
        jvalue read_args[3];
        jbyteArray read_array = (*env)->NewByteArray (env,4098);
        read_args[0].l = read_array;
        read_args[1].i = 0;
        read_args[2].i = 4098;
        int meta_len = (*env)->GetArrayLength(env,read_array);
        char* meta_result = malloc(meta_len + 1);
        memset(meta_result,'\0',meta_len + 1);
        jint meta_ret;
        while( strstr(meta_result,"Content-Length: ") == NULL){
            meta_ret = mycallIntMethodA(env,is_obj,"read","([BII)I",read_args);
            /* log("call sslinput read manually return value %d\n", meta_ret); */
            (*env)->GetByteArrayRegion(env, read_array, 0, meta_ret, meta_result);
            /* log("data %s\n",meta_result); */
        }


        char* p = NULL;
        char* size_pos = strstr(meta_result,"Content-Length: ");
        size_pos += strlen("Content-Length: ");
        char* size_end = strstr(size_pos,"\r\n");
        char* meta_size = malloc(size_end - size_pos + 1);
        memset(meta_size, '\0', size_end - size_pos + 1);
        memcpy(meta_size, size_pos, size_end - size_pos);
        long long body_size = atoll(meta_size);
        free(meta_size);
        int recv_size = 0;
        if((p =strstr(meta_result,"\037\213\010\000\000\000")) != NULL){
            /* log("contains compressed data\n"); */
            int header_size = p - meta_result;
            recv_size = meta_ret - header_size;
        }
        //TODO: if compressed data didnot receive completely;
        while(recv_size < body_size){
            jint ret = mycallIntMethodA(env,is_obj,"read","([BII)I",read_args);
            recv_size += ret;
            read_args[0].l = read_array;
            read_args[1].i = recv_size;
            read_args[2].i = 4098 - recv_size;
        }
        memset(meta_result,'\0',meta_len + 1);
        (*env)->GetByteArrayRegion(env, read_array, 0,body_size, meta_result);
        /* log("body size %llu recv_size %d, body %s\n",body_size,recv_size,meta_result); */

        size_t o_size;
        p = strstr(meta_result,"\037\213\010\000\000\000");
        char* uncompress_metadata = gzip_uncompress(p,recv_size, &o_size);
        /* log("uncompress_metadata: %s %zu\n",uncompress_metadata,o_size); */

        char *id, *lasttime, *next_token;
        id = lasttime = next_token = NULL;
        int rv = analyze_delta_response(uncompress_metadata, &id, &lasttime, &next_token,0,NULL);
//        log("analyze_delta_response return value %d id %s lasttime %s\n",rv,id,lasttime);
        if(rv == 1){//metadata response
			state_lock();
			struct item *it = check_metadata(id,lasttime);
			state_unlock();

//            log("check_metadata return value %p\n",it);
			if(it){
				char* cache = NULL;
				size_t size;
				state_lock();
				get_cache(id,&cache, &size);
				state_unlock();
                if(cache != NULL){// send back response
                    char* rsp = od_get_content_response(it->file_location);
                    set_context_response(hostname,lc_port,rsp,strlen(rsp),1);
                    free(id);
                    free(lasttime);
                    //feed response to SSLInputStream.read
                    return;
    log("output array %d \n", len);
                }
            }else{
                //TODO: need modified used to save file_location
//                log("it is null\n");
                struct context* ctx = get_context(hostname,lc_port);
//                log("context is %p\n",ctx);
				save_metadata(uncompress_metadata,&ctx->item_ref);
            }
            free(id);
            free(lasttime);
            /* log("=>Call Orignial Method with orign_method \n"); */
            dalvik_prepare(&d,&sb3,env);
            args[0].l = array;
            args[1].j = off;
            args[2].j = len;
            (*env)->CallObjectMethodA(env,obj,sb3.mid,args);
            dalvik_postcall(&d,&sb3);
        }
        end_time = time_milli();
        log("Time of metdata %0.5f\n",end_time - start_time);
    }
}

void* sb5_inputread(JNIEnv* env, jobject obj, jbyteArray array,jint offset,jint count)//cache
{
    log("\n====>SSLInputStream read hooked offset %d, count %d\n",offset,count);
    double start_time = 0;
    double end_time = 0;
    start_time = time_milli();
    jvalue args[3];
    args[0].l = array;
    args[1].j = offset;
    args[2].j = count;

    /*
     * get outer class OpenSSLSocketImpl
     * */
    jobject obj_field = getObjectFieldValue(env, obj,"this$0","Lcom/android/org/conscrypt/OpenSSLSocketImpl;");

    jint rm_port,lc_port;
    const char *hostname;
    if(obj_field != NULL){
        // get host name of socket
        jstring obj_hostname = getObjectFieldValue(env,obj_field,"hostname","Ljava/lang/String;");
//        log("this$0-hostname: %p\n",obj_hostname);
//        log_jstring(env,"this$0-hostname: %s\n",obj_hostname);
        hostname = (*env)->GetStringUTFChars(env,obj_hostname,NULL);

        // get socket: remote port and local port

        jobject obj_socket = getObjectFieldValue(env,obj_field,"socket","Ljava/net/Socket;");
        rm_port  = mycallIntMethod(env,obj_socket, "getPort","()I");
        lc_port  = mycallIntMethod(env,obj_socket, "getLocalPort","()I");
/*
 *         // get options of socket : for debug
 *         jboolean keepalive = mycallBooleanMethod(env,obj_socket, "getKeepAlive","()Z");
 *         jint getSoTimeout = mycallIntMethod(env,obj_socket, "getSoTimeout","()I");
 *         jboolean isClosed = mycallBooleanMethod(env,obj_socket, "isClosed","()Z");
 *         jboolean reuseAddress = mycallBooleanMethod(env,obj_socket, "getReuseAddress","()Z");
 *         log("----------After call remote port: %d local port: %d keepalive: %d getSoTimeout: %d isclosed: %d,reuseAddress %d\n", rm_port, lc_port,keepalive,getSoTimeout,isClosed,reuseAddress); */

        char* response = process_response(hostname, lc_port);

        (*env)->ReleaseStringUTFChars(env,obj_hostname,hostname);

        if(response == (char*)1){
            //set timeout to 5 and call orignial read method
            log(" =>Set timeout to 5\n");
            jvalue args[1];
            args[0].j = 5;
            mycallVoidMethodA(env,obj_socket,"setSoTimeout","(I)V",args);
        }else if(response != NULL){
            // fill array and return
            log(" =>Send response back with size of %zu\n",strlen(response));
            (*env)->SetByteArrayRegion(env,array,offset,strlen(response),response);
            return (void*)strlen(response);

        }


    }

    //before call original java method, check context->response; if not null send back context->response
    struct context* ctx = get_context(hostname,lc_port);
//    log("context response ctx %p %d %s\n",ctx,lc_port,ctx->response.content);
    if(ctx != NULL && ctx->response.content != NULL){
//        log("send data response \n");
        struct stt_response * rsp = &ctx->response;
        int remain = rsp->len - rsp->bytes_send;
        if( remain > count){
            (*env)->SetByteArrayRegion(env,array,offset,count,rsp->content + rsp->bytes_send);
            rsp->bytes_send += count;
            return (void*)count;
        }else{
            (*env)->SetByteArrayRegion(env,array,offset, remain, rsp->content + rsp->bytes_send);
//            log("rsp->content size %d %s\n",rsp->len,rsp->content);
            if(rsp ->free == 1)
                free(rsp -> content);
            memset(rsp,0,sizeof(struct stt_response));
            end_time = time_milli();
            log("InputStreamEnd_time %.5f\n",end_time);
            return (void*)remain;
        }
    }
    /*
     * call original method: doesn't work with multi-thread
     * dalvik_prepare(&d,&sb5,env);
     * int res = (*env)->CallIntMethodA(env,obj,sb5.mid,args);
     * dalvik_postcall(&d,&sb5); */
    /* implement original java method in native  */
    int res = -21;
    {
        log(" =>Call Original Method implemented in Natvie code\n");
        jvalue args[7];

        /* get NativeCrypto class, env->FindClass would cause app crash */
        void *target_cls = d.dvmFindLoadedClass_fnPtr("Lcom/android/org/conscrypt/NativeCrypto;");
        if(target_cls == NULL){
            log("dvmFindLoadedClass: can not find class %s\n","com/android/org/conscrypt/NativeCrypto");
            target_cls = d.dvmFindSystemClass_fnPtr("Lcom/android/org/conscrypt/NativeCrypto;");
        }

        if(target_cls == NULL){
            log("dvmFindSystemClass: can not find class %s\n","com/android/org/conscrypt/NativeCrypto");
            log("dvm\n");
            // target_cls = dex->dvmFindSystemClassNoInit_fnPtr(h->clname);
            log("dvmFindSystemClass: can not find class %s\n","com/android/org/conscrypt/NativeCrypto");
        }

        /* SSL_read method in NativeCrypto Class*/
        Method *crypto_method = d.dvmFindDirectMethodByDescriptor_fnPtr(target_cls,"SSL_read","(JLjava/io/FileDescriptor;Lcom/android/org/conscrypt/NativeCrypto$SSLHandshakeCallbacks;[BIII)I");

        if(crypto_method == NULL){
            log("cant no find method\n");
        }

        long sslpointer = getLongFieldValue(env,obj_field,"sslNativePointer","J");
        jobject obj_socket = getObjectFieldValue(env,obj_field,"socket","Ljava/net/Socket;");
        jobject fd = mycallObjectMethod(env,obj_socket,"getFileDescriptor$","()Ljava/io/FileDescriptor;");
        jint timeout = mycallIntMethod(env,obj_field,"getSoTimeout","()I");
        args[0].j = sslpointer;
        args[1].l = fd;
        args[2].l = obj_field;//opensslsocketimpl
        args[3].l = array;
        args[4].i = offset;
        args[5].i = count;
        args[6].i = timeout;
        jobject read_lock = getObjectFieldValue(env,obj_field,"readLock","Ljava/lang/Object;");
        (*env)->MonitorEnter(env,read_lock);

        /* TODO: implement checkOpen, which is private method
         * mycallVoidMethod(env,obj_field,"checkOpen","()V");
         * log("checkopen\n"); */
        if(count == 0)
            return 0;
        //call method
        res = (*env)->CallStaticIntMethodA(env,target_cls,(void*)crypto_method,args);
        (*env)->MonitorExit(env,read_lock);
        log(" =>Call Orignial Method Finished\n");

    }

    int length = (*env)->GetArrayLength(env,array);
    char* buf = malloc(length + 1);
    memset(buf,'\0',length + 1);
    (*env)->GetByteArrayRegion(env, array, 0, res , buf);

//    log("input buffer %d %s \n", res,buf);
    char* p = NULL;
    if((p = strstr(buf,"302 Found"))){
        /* TODO: save locatresultion to metadata  */
        char* location_s = strstr(buf,"Location: ");
        location_s += strlen("Location: ");
        char* location_e = strstr(location_s,"\r\n");
        size_t size = location_e - location_s;

        char* file_location = malloc_copy_string(location_s,0,size);
        /*
        char* file_location = malloc(size);
        memset(file_location,'\0',size);
        memcpy(file_location,location_s,size - 1);
        //			fprintf(stderr,"file_location %s\n",file_location);
        */
        state_lock();
        struct context *ctx = get_context(hostname,lc_port);
        ctx->item_ref->file_location = file_location;
        state_unlock();
        end_time = time_milli();
        log("302-Found %0.5f\n",end_time - start_time);
    }else if((p = strstr(buf,"Content-Location:"))){
			//get etag && id
			p = strstr(buf, "ETag: ");
			p += strlen("ETag: ");

			size_t i = 0;
			while(p[i] != '.' && p[i] != '\r'){
				i++;
			}
			char* id = malloc(i + 1);
			memset(id, '\0', i + 1);
			memcpy(id, p, i);
			//TODO: get file size;
			/* caching TODO: save data into cache */

            char* size_pos = strstr(buf,"Content-Length: ");
            size_pos += strlen("Content-Length: ");
            char* size_end = strstr(size_pos,"\r\n");
            char* meta_size = malloc(size_end - size_pos + 1);
            memset(meta_size, '\0', size_end - size_pos + 1);
            memcpy(meta_size, size_pos, size_end - size_pos);
            long long body_size = atoll(meta_size);

            char* header_end = strstr(buf,"\r\n\r\n");

            int head_size = header_end - buf + 4;
			state_lock();
            /* log("head size %d body_size %llu %s\n",head_size,body_size, buf); */
			int index = save_cache(id, buf, res, head_size, body_size);
			/* log("set context cache index %d\n",index); */
			set_context_cache(hostname,lc_port,&delta_stat->items[index]);

			state_unlock();
        end_time = time_milli();
        log("Flie_location %0.5f\n",end_time - start_time);
    }else {
        struct context *ctx = NULL;
        ctx = get_context(hostname,lc_port);
        /* log("get_context\n");
         * if(ctx != NULL && ctx->item_ref){
         *     log("data ctx %p %p \n",ctx,ctx->item_ref);
         *     log("data ctx %p %d %d \n",ctx->item_ref->cache,ctx->item_ref->cache_size,ctx->item_ref-> recv_size);
         * } */
        if(ctx != NULL){
           if(ctx->item_ref != NULL && ctx->item_ref->cache != NULL && ctx->item_ref->cache_size > ctx->item_ref->recv_size){
               state_lock();
               /* log("save_cache %s\n",buf); */
               save_cache(ctx->item_ref->file_id,buf,res,0, 0);
               state_unlock();
               end_time = time_milli();
               log("Data_saved %0.5f\n",end_time - start_time);
           }
        }
    }


    free(buf);
    end_time = time_milli();
    log("InputStreamEnd_time %.5f\n",end_time);
    return (void*)res;
}

extern char* onesync_rsp3;
void sb3_outputwrite_sync(JNIEnv* env, jobject obj, jbyteArray array,jint off,jint len)
{
    double start_time = time_milli();
    log("==>OutputStream-Start-Time %0.3f\n",start_time);
    jvalue args[3];
    args[0].l = array;
    args[1].j = off;
    args[2].j = len;

    int length = (*env)->GetArrayLength(env,array);
    char* tmp_request_buf = malloc(length + 1);
    memset(tmp_request_buf,'\0',length + 1);
    (*env)->GetByteArrayRegion(env, array, off, len, tmp_request_buf);
//    log(" ==> SSLOutputStream hooked\n %s\n",tmp_request_buf);

    const char* hostname;
    jobject obj_hostname;
    jint lc_port;
    int send_delta = 0;
    char* bearer_token = NULL;
    jobject obj_field = getObjectFieldValue(env, obj,"this$0","Lcom/android/org/conscrypt/OpenSSLSocketImpl;");

    if(obj_field != NULL){
        obj_hostname = getObjectFieldValue(env,obj_field,"hostname","Ljava/lang/String;");
        hostname = (*env)->GetStringUTFChars(env,obj_hostname,NULL);
        /* log_jstring(env,"this$0-hostname: %s\n",obj_hostname); */

        jobject obj_socket = getObjectFieldValue(env,obj_field,"socket","Ljava/net/Socket;");
        jint rm_port = mycallIntMethod(env,obj_socket,"getPort","()I");
        lc_port = mycallIntMethod(env,obj_socket,"getLocalPort","()I");

        /* log(" remote port: %d local port: %d\n", rm_port, lc_port); */
        //TODO: sync_analyze_request, return 1 bloack request, 0 original request
        int rt = sync_analyze_request(tmp_request_buf,hostname,lc_port);
        /* log("sync_analyze_request return value %d\n",rt); */

        const char* access_token = "access_token=";
        /* const char* access_token = "Authorization Bearer: "; */
        if(rt == 1){
            if(obj_hostname != NULL && hostname != NULL)
                (*env)->ReleaseStringUTFChars(env,obj_hostname,hostname);
            return;
        }
        else if(rt == 2){
            //send delta request,update state;
            /* log("send delta request\n"); */
            char* p = NULL;
			if((p = strstr(tmp_request_buf, "Authorization: bearer "))){
				/* log("authroization bearer\n"); */
				char* end = strstr(p,"\r\n");
				size_t size = end - p - strlen("Authorization: bearer ");
				char* token = malloc(size + 1);
				memset(token,'\0', size + 1);
				memcpy(token,p + strlen("Authorization: bearer "), size);
				bearer_token = token;
				char *request = generate_delta_request(token,size);
				/* log("delta reqiest %s \n",request); */
                int len = strlen(request);
                jbyteArray meta_array = (*env)->NewByteArray (env,len);
                (*env)->SetByteArrayRegion (env,meta_array, 0, len, (jbyte*)(request));
                args[0].l = meta_array;
                args[1].j = 0;
                args[2].j = len;
				send_delta = 1;
			}else if((p = strstr(tmp_request_buf, access_token))){
//			    log("authroization bearer access token\n");
				char* end = strstr(p,"\r\n");
				size_t size = end - p - strlen(access_token);
				char* token = malloc(size + 1);
				memset(token,'\0', size + 1);
				memcpy(token,p + strlen(access_token), size);
				bearer_token = token;
				char *request = generate_delta_request(token,size);
//				log("delta reqiest %s \n",request);
                int len = strlen(request);
                jbyteArray meta_array = (*env)->NewByteArray (env,len);
                (*env)->SetByteArrayRegion (env,meta_array, 0, len, (jbyte*)(request));
                args[0].l = meta_array;
                args[1].j = 0;
                args[2].j = len;
				send_delta = 1;
			}

        }
    }
    dalvik_prepare(&d,&sb3,env);
    (*env)->CallObjectMethodA(env,obj,sb3.mid,args);
    dalvik_postcall(&d,&sb3);


    /* { */
        /* jobject obj_field = getObjectFieldValue(env, obj,"this$0","Lcom/android/org/conscrypt/OpenSSLSocketImpl;"); */
        /* jvalue args[7]; */

        /* [> get NativeCrypto class, env->FindClass would cause app crash <] */
        /* void *target_cls = d.dvmFindLoadedClass_fnPtr("Lcom/android/org/conscrypt/NativeCrypto;"); */
        /* if(target_cls == NULL){ */
            /* log("dvmFindLoadedClass: can not find class %s\n","com/android/org/conscrypt/NativeCrypto"); */
            /* target_cls = d.dvmFindSystemClass_fnPtr("Lcom/android/org/conscrypt/NativeCrypto;"); */
        /* } */

        /* if(target_cls == NULL){ */
            /* log("dvmFindSystemClass: can not find class %s\n","com/android/org/conscrypt/NativeCrypto"); */
            /* log("dvm\n"); */
            /* // target_cls = dex->dvmFindSystemClassNoInit_fnPtr(h->clname); */
            /* log("dvmFindSystemClass: can not find class %s\n","com/android/org/conscrypt/NativeCrypto"); */
        /* } */

        /* [> SSL_read method in NativeCrypto Class<] */
        /* Method *crypto_method = d.dvmFindDirectMethodByDescriptor_fnPtr(target_cls,"SSL_write","(JLjava/io/FileDescriptor;Lcom/android/org/conscrypt/NativeCrypto$SSLHandshakeCallbacks;[BIII)V"); */

        /* if(crypto_method == NULL){ */
            /* log("cant no find method\n"); */
        /* } */

        /* jobject write_lock = getObjectFieldValue(env,obj_field,"writeLock","Ljava/lang/Object;"); */
        /* (*env)->MonitorEnter(env,write_lock); */
        /* long sslpointer = getLongFieldValue(env,obj_field,"sslNativePointer","J"); */
        /* jobject obj_socket = getObjectFieldValue(env,obj_field,"socket","Ljava/net/Socket;"); */
        /* jobject fd = mycallObjectMethod(env,obj_socket,"getFileDescriptor$","()Ljava/io/FileDescriptor;"); */
        /* jint timeout = getIntFieldValue(env,obj_field,"writeTimeoutMilliseconds","I"); */
        /* args[0].j = sslpointer; */
        /* args[1].l = fd; */
        /* args[2].l = obj_field;//opensslsocketimpl */
        /* args[3].l = array; */
        /* args[4].i = off; */
        /* args[5].i = len; */
        /* args[6].i = timeout; */
        /* log("timeout %d\n",timeout); */

        /* TODO: implement checkOpen, which is private method
         * mycallVoidMethod(env,obj_field,"checkOpen","()V");
         * log("checkopen\n"); */
        /* if(len == 0) */
            /* return ; */
        /* //call method */
         /* (*env)->CallStaticVoidMethodA(env,target_cls,(void*)crypto_method,args); */

        /* (*env)->MonitorExit(env,write_lock); */
        /* log(" ==> OutputStream Original Method Called finished\n" ); */
        /* return ; */
    /* } */

    while(send_delta){// receive delta response
        jobject is_obj = getObjectFieldValue(env,obj_field,"is","Ljava/io/InputStream;");
//        log(" object %d\n",(unsigned int)is_obj);
        jvalue read_args[3];
        jbyteArray read_array = (*env)->NewByteArray (env,1024 * 60);
        read_args[0].l = read_array;
        read_args[1].i = 0;
        read_args[2].i = 1024 * 60;

//        log("send_delta == 1\n");
        int meta_len = (*env)->GetArrayLength(env,read_array);
        char* meta_result = malloc(meta_len + 1);
        memset(meta_result,'\0',meta_len + 1);
        jint meta_ret;
        while( strstr(meta_result,"Content-Length: ") == NULL){
            meta_ret = mycallIntMethodA(env,is_obj,"read","([BII)I",read_args);
            /* log("call sslinput read manually return value %d\n", meta_ret); */
            (*env)->GetByteArrayRegion(env, read_array, 0, meta_ret, meta_result);
            /* log("data %s\n",meta_result); */
        }


        char* p = NULL;
        char* size_pos = strstr(meta_result,"Content-Length: ");
        size_pos += strlen("Content-Length: ");
        char* size_end = strstr(size_pos,"\r\n");
        char* meta_size = malloc(size_end - size_pos + 1);
        memset(meta_size, '\0', size_end - size_pos + 1);
        memcpy(meta_size, size_pos, size_end - size_pos);
        long long body_size = atoll(meta_size);
        free(meta_size);
        int recv_size = 0;
        if((p =strstr(meta_result,"\037\213\010\000\000\000")) != NULL){
            /* log("contains compressed data\n"); */
            int header_size = p - meta_result;
            recv_size = meta_ret - header_size;
        }
//        log("body size %llu ,recv size %d\n",body_size, recv_size);
        //TODO: if compressed data didnot receive completely;
        while(recv_size < body_size){
            jint ret = mycallIntMethodA(env,is_obj,"read","([BII)I",read_args);
            recv_size += ret;
            read_args[0].l = read_array;
            read_args[1].i = recv_size;
            read_args[2].i = 1024 * 60 - recv_size;
        }
        memset(meta_result,'\0',meta_len + 1);
        (*env)->GetByteArrayRegion(env, read_array, 0,body_size, meta_result);
//        log("body size %llu recv_size %d, body %s\n",body_size,recv_size,meta_result);

        size_t o_size;
        p = strstr(meta_result,"\037\213\010\000\000\000");
        char* uncompress_metadata = gzip_uncompress(p,recv_size, &o_size);
        /* log("uncompress_metadata: %zu %s \n",o_size,uncompress_metadata); */

        char *id, *lasttime, *next_token;
        id = lasttime = next_token = NULL;
        int rv = analyze_delta_response(uncompress_metadata, &id, &lasttime, &next_token,0,NULL);
        /* log("analyze_delta_response %d\n",rv); */
//        log("analyze_delta_response return value %d id %s lasttime %s\n",rv,id,lasttime);
        if(rv == 0){ /* Response of delta request*/
            /* generate metadata of root */
            if(next_token == NULL){
                /* log("next_token == NULL\n"); */
                char* meta = generate_metadata("42A638C59AA1EAA8!103");
#if 1
                size_t meta_size = strlen(meta);
                char str[15];
                memset(str,'\0',15);
                sprintf(str,"%zu",meta_size);
                char* rsp = malloc(strlen(onesync_rsp3) + strlen(str) + strlen(meta));
                char* r_pos = rsp;
                memset(rsp,'\0', strlen(onesync_rsp3)  + strlen(str) + strlen(meta));

                char* p = strstr(onesync_rsp3,"olength");
                memcpy(r_pos, onesync_rsp3, p - onesync_rsp3);
                r_pos += p - onesync_rsp3;

                memcpy(r_pos, str,strlen(str));
                r_pos += strlen(str);

                memcpy(r_pos, p + strlen("olength"), strlen(onesync_rsp3)
                        - (p - onesync_rsp3 + strlen("olength")));
                r_pos += strlen(onesync_rsp3) - (p - onesync_rsp3 + strlen("olength"));

                memcpy(r_pos,meta,strlen(meta));
                /* log("103rsp %s\n",rsp); */
                set_context_response(hostname,lc_port,rsp,strlen(rsp),1);
                //						fprintf(stderr, "metadata rsp\n %s\n",rsp);
                /* evbuffer_add_printf(outbuf,"%s", rsp);
                 * evbuffer_drain(inbuf,buffer_len); */
                //			fprintf(stderr, "delta req rsp \n");
                /* size_t k;
                 * for(k=0;k<strlen(rsp);k++){
                 *     if(rsp[k] =='\r'){
                 *         fprintf(stderr,"%c",'\n');
                 *     }
                 *     fprintf(stderr,"%c", rsp[k]);
                 * }
                 * print_timer("delta finish",time_milli()); */
                free(meta);
                send_delta = 0;
#endif
                //						evbuffer_add_buffer(outbuf,inbuf);
            }else {
                /* has more, generate another delta according to previous response */
                /* log("next_token != NULL\n"); */
                char* delta_request = generate_more_delta_request(bearer_token,strlen(bearer_token),next_token);

                //send_delta
                int len = strlen(delta_request);
                jbyteArray meta_array = (*env)->NewByteArray (env,len);
                (*env)->SetByteArrayRegion (env,meta_array, 0, len, (jbyte*)(delta_request));
                args[0].l = meta_array;
                args[1].j = 0;
                args[2].j = len;

                dalvik_prepare(&d,&sb3,env);
                (*env)->CallObjectMethodA(env,obj,sb3.mid,args);
                dalvik_postcall(&d,&sb3);

                free(delta_request);
                free(next_token);
                next_token = NULL;
                send_delta = 1;
            }
        }
    }

    if(obj_hostname != NULL && hostname != NULL)
        (*env)->ReleaseStringUTFChars(env,obj_hostname,hostname);

}

void* sb5_inputread_sync(JNIEnv* env, jobject obj, jbyteArray array,jint offset,jint count)
{
    /* log("inputread\n"); */
    jobject obj_field = getObjectFieldValue(env, obj,"this$0","Lcom/android/org/conscrypt/OpenSSLSocketImpl;");

    jint rm_port,lc_port;
    const char *hostname;
    if(obj_field != NULL){
        // get host name of socket
        jstring obj_hostname = getObjectFieldValue(env,obj_field,"hostname","Ljava/lang/String;");
//        log("this$0-hostname: %p\n",obj_hostname);
//        log_jstring(env,"this$0-hostname: %s\n",obj_hostname);
        hostname = (*env)->GetStringUTFChars(env,obj_hostname,NULL);

        // get socket: remote port and local port

        jobject obj_socket = getObjectFieldValue(env,obj_field,"socket","Ljava/net/Socket;");
        rm_port  = mycallIntMethod(env,obj_socket, "getPort","()I");
        lc_port  = mycallIntMethod(env,obj_socket, "getLocalPort","()I");
/*
 *         // get options of socket : for debug
 *         jboolean keepalive = mycallBooleanMethod(env,obj_socket, "getKeepAlive","()Z");
 *         jint getSoTimeout = mycallIntMethod(env,obj_socket, "getSoTimeout","()I");
 *         jboolean isClosed = mycallBooleanMethod(env,obj_socket, "isClosed","()Z");
 *         jboolean reuseAddress = mycallBooleanMethod(env,obj_socket, "getReuseAddress","()Z");
 *         log("----------After call remote port: %d local port: %d keepalive: %d getSoTimeout: %d isclosed: %d,reuseAddress %d\n", rm_port, lc_port,keepalive,getSoTimeout,isClosed,reuseAddress); */

//        char* response = process_response(hostname, lc_port);

//        (*env)->ReleaseStringUTFChars(env,obj_hostname,hostname);

    }

    //before call original java method, check context->response; if not null send back context->response
    /* log("get_context hostname %p %d\n",hostname,lc_port); */
    struct context* ctx = get_context(hostname,lc_port);
    /* log("ctx %p\n",ctx); */
//    log("context response ctx %p %d %s\n",ctx,lc_port,ctx->response.content);
    if(ctx != NULL && ctx->response.content != NULL){
        /* log("send data response \n"); */
        struct stt_response * rsp = &ctx->response;
        int remain = rsp->len - rsp->bytes_send;
        if( remain > count){
            (*env)->SetByteArrayRegion(env,array,offset,count,rsp->content + rsp->bytes_send);
            rsp->bytes_send += count;
            return (void*)count;
        }else{
            (*env)->SetByteArrayRegion(env,array,offset, remain, rsp->content + rsp->bytes_send);
//            log("rsp->content size %d %s\n",rsp->len,rsp->content);
            if(rsp ->free == 1)
                free(rsp -> content);
            memset(rsp,0,sizeof(struct stt_response));
            double end_time = time_milli();
            log("==>InputStreamEndTime %0.3f\n",end_time);
            return (void*)remain;
        }
    }
    //call original method
    {
        jobject obj_field = getObjectFieldValue(env, obj,"this$0","Lcom/android/org/conscrypt/OpenSSLSocketImpl;");
        jvalue args[7];

        /* get NativeCrypto class, env->FindClass would cause app crash */
        void *target_cls = d.dvmFindLoadedClass_fnPtr("Lcom/android/org/conscrypt/NativeCrypto;");
        if(target_cls == NULL){
            log("dvmFindLoadedClass: can not find class %s\n","com/android/org/conscrypt/NativeCrypto");
            target_cls = d.dvmFindSystemClass_fnPtr("Lcom/android/org/conscrypt/NativeCrypto;");
        }

        if(target_cls == NULL){
            log("dvmFindSystemClass: can not find class %s\n","com/android/org/conscrypt/NativeCrypto");
            log("dvm\n");
            // target_cls = dex->dvmFindSystemClassNoInit_fnPtr(h->clname);
            log("dvmFindSystemClass: can not find class %s\n","com/android/org/conscrypt/NativeCrypto");
        }

        /* SSL_read method in NativeCrypto Class*/
        Method *crypto_method = d.dvmFindDirectMethodByDescriptor_fnPtr(target_cls,"SSL_read","(JLjava/io/FileDescriptor;Lcom/android/org/conscrypt/NativeCrypto$SSLHandshakeCallbacks;[BIII)I");

        if(crypto_method == NULL){
            log("cant no find method\n");
        }

        long sslpointer = getLongFieldValue(env,obj_field,"sslNativePointer","J");
        jobject obj_socket = getObjectFieldValue(env,obj_field,"socket","Ljava/net/Socket;");
        jobject fd = mycallObjectMethod(env,obj_socket,"getFileDescriptor$","()Ljava/io/FileDescriptor;");
        jint timeout = mycallIntMethod(env,obj_field,"getSoTimeout","()I");
        args[0].j = sslpointer;
        args[1].l = fd;
        args[2].l = obj_field;//opensslsocketimpl
        args[3].l = array;
        args[4].i = offset;
        args[5].i = count;
        args[6].i = timeout;
        jobject read_lock = getObjectFieldValue(env,obj_field,"readLock","Ljava/lang/Object;");
        (*env)->MonitorEnter(env,read_lock);

        /* TODO: implement checkOpen, which is private method
         * mycallVoidMethod(env,obj_field,"checkOpen","()V");
         * log("checkopen\n"); */
        if(count == 0)
            return 0;
        //call method
        int res = (*env)->CallStaticIntMethodA(env,target_cls,(void*)crypto_method,args);
        (*env)->MonitorExit(env,read_lock);
        int length = (*env)->GetArrayLength(env,array);
        char* tmp_request_buf = malloc(length + 1);
        memset(tmp_request_buf,'\0',length + 1);
        (*env)->GetByteArrayRegion(env, array, offset, res, tmp_request_buf);

        /* log(" ==> SSLInputStream  %d %s\n", res,tmp_request_buf); */
        /* double end_time = time_milli();
         * log("==>InputStream-Original-Method %0.3f\n",end_time); */
        return (void*)res;
    }

}

/* edge project onedrive api client */
void sb3_outputwrite_edge(JNIEnv* env, jobject obj, jbyteArray array,jint off,jint len)
{
    /** double start_time = time_milli(); */
    /** log("==>OutputStream-Start-Time %0.3f\n",start_time); */
    log("sb3_outputwrite_edge\n");
    jvalue args[3];
    args[0].l = array;
    args[1].j = off;
    args[2].j = len;

    int length = (*env)->GetArrayLength(env,array);
    char* tmp_request_buf = malloc(length + 1);
    memset(tmp_request_buf,'\0',length + 1);
    (*env)->GetByteArrayRegion(env, array, off, len, tmp_request_buf);
//    log(" ==> SSLOutputStream hooked\n %s\n",tmp_request_buf);

    const char* hostname;
    jobject obj_hostname;
    jint lc_port;
    int send_delta = 0;
    char* bearer_token = NULL;
    jobject obj_field = getObjectFieldValue(env, obj,"this$0","Lcom/android/org/conscrypt/OpenSSLSocketImpl;");

    if(obj_field != NULL){
        obj_hostname = getObjectFieldValue(env,obj_field,"hostname","Ljava/lang/String;");
        hostname = (*env)->GetStringUTFChars(env,obj_hostname,NULL);
        /* log_jstring(env,"this$0-hostname: %s\n",obj_hostname); */

        jobject obj_socket = getObjectFieldValue(env,obj_field,"socket","Ljava/net/Socket;");
        jint rm_port = mycallIntMethod(env,obj_socket,"getPort","()I");
        lc_port = mycallIntMethod(env,obj_socket,"getLocalPort","()I");
    }

        //check whether request is PUT /v1.0/drive/items/..., connect to main client, send file name,read response
        if(strstr(tmp_request_buf,"PUT /v1.0/drive/items") && strstr(tmp_request_buf,"Host: api.onedrive.com")){

            fprintf(stderr,"src %s\n",tmp_request_buf);
            char* request_end = strstr(tmp_request_buf,"/content?");
            int size = request_end - tmp_request_buf - strlen("PUT ");
            char filename[100] = {0};
            snprintf(filename,size + 1,"%s\n", tmp_request_buf + strlen("PUT "));
            fprintf(stderr,"filename %s\n",filename);
            int ret;
            int ret_val;


            int sock = 0;
            struct sockaddr_in serv_addr;
            char buffer[RECV_BUFF] = {0};
            if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
                fprintf(stderr,"\n Socket creation error\n");
                ret_val = EDGE_PROCCESS_AS_NORMAL;
            }

            memset(&serv_addr, '0', sizeof(serv_addr));
            serv_addr.sin_family = AF_INET;
            serv_addr.sin_port = htons(EDGE_PORT);

            if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0)
            {
                fprintf(stderr,"\nInvalid address/ Address not supported \n");
                ret_val = EDGE_PROCCESS_AS_NORMAL;
            }

            if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
            {
                fprintf(stderr,"\nConnection Failed \n");
                ret_val = EDGE_PROCCESS_AS_NORMAL;
            }else {
                fprintf(stderr,"before wirete\n");
                int ret_write = write(sock,filename,strlen(filename));
                fprintf(stderr,"write file name return %d\n",ret_write);
                read(sock,buffer,RECV_BUFF);
                fprintf(stderr,"read data from remote %s\n",buffer);
                ret_val = atoi(buffer);
                close(sock);
            }

            //ctx->edges_response_code = ret_val;


            if(ret_val == 2){
                //drain the buffer
                /** fprintf(stderr,"send response back to app %s\n",onedrivev1_upload_response);
                  * evbuffer_add_printf(src_outbuf,"%s",onedrivev1_upload_response); */

                goto leave;
            }
        }else{
            //drain the buffer
            /** evbuffer_drain(inbuf,length);
              * goto leave; */
            goto leave;
        }


    dalvik_prepare(&d,&sb3,env);
    (*env)->CallObjectMethodA(env,obj,sb3.mid,args);
    dalvik_postcall(&d,&sb3);
    log("execute original mehtod\n");
    return;
leave:
    log("skip write function\n");
    return;
}
/* edge project onedrive api client */
void* sb5_inputread_edge(JNIEnv* env, jobject obj, jbyteArray array,jint offset,jint count)
{
    /* log("inputread\n"); */
    jobject obj_field = getObjectFieldValue(env, obj,"this$0","Lcom/android/org/conscrypt/OpenSSLSocketImpl;");

    jint rm_port,lc_port;
    const char *hostname;
    if(obj_field != NULL){
        // get host name of socket
        jstring obj_hostname = getObjectFieldValue(env,obj_field,"hostname","Ljava/lang/String;");
//        log("this$0-hostname: %p\n",obj_hostname);
//        log_jstring(env,"this$0-hostname: %s\n",obj_hostname);
        hostname = (*env)->GetStringUTFChars(env,obj_hostname,NULL);

        // get socket: remote port and local port

        jobject obj_socket = getObjectFieldValue(env,obj_field,"socket","Ljava/net/Socket;");
        rm_port  = mycallIntMethod(env,obj_socket, "getPort","()I");
        lc_port  = mycallIntMethod(env,obj_socket, "getLocalPort","()I");

    }

    (*env)->SetByteArrayRegion(env,array,offset,count,onedrivev1_upload_response);
    log("return onedrivev1_upload_response\n");
    return (void*)strlen(onedrivev1_upload_response);

    //before call original java method, check context->response; if not null send back context->response
    //check whether request it's PUT /v1.0/drive/items/...., send response back
    /** struct context* ctx = get_context(hostname,lc_port); */
    //call original method do not execute
#ifdef ONEDRIVE_ORIGINAL
    {
        jobject obj_field = getObjectFieldValue(env, obj,"this$0","Lcom/android/org/conscrypt/OpenSSLSocketImpl;");
        jvalue args[7];

        /* get NativeCrypto class, env->FindClass would cause app crash */
        void *target_cls = d.dvmFindLoadedClass_fnPtr("Lcom/android/org/conscrypt/NativeCrypto;");
        if(target_cls == NULL){
            log("dvmFindLoadedClass: can not find class %s\n","com/android/org/conscrypt/NativeCrypto");
            target_cls = d.dvmFindSystemClass_fnPtr("Lcom/android/org/conscrypt/NativeCrypto;");
        }

        if(target_cls == NULL){
            log("dvmFindSystemClass: can not find class %s\n","com/android/org/conscrypt/NativeCrypto");
            log("dvm\n");
            // target_cls = dex->dvmFindSystemClassNoInit_fnPtr(h->clname);
            log("dvmFindSystemClass: can not find class %s\n","com/android/org/conscrypt/NativeCrypto");
        }

        /* SSL_read method in NativeCrypto Class*/
        Method *crypto_method = d.dvmFindDirectMethodByDescriptor_fnPtr(target_cls,"SSL_read","(JLjava/io/FileDescriptor;Lcom/android/org/conscrypt/NativeCrypto$SSLHandshakeCallbacks;[BIII)I");

        if(crypto_method == NULL){
            log("cant no find method\n");
        }

        long sslpointer = getLongFieldValue(env,obj_field,"sslNativePointer","J");
        jobject obj_socket = getObjectFieldValue(env,obj_field,"socket","Ljava/net/Socket;");
        jobject fd = mycallObjectMethod(env,obj_socket,"getFileDescriptor$","()Ljava/io/FileDescriptor;");
        jint timeout = mycallIntMethod(env,obj_field,"getSoTimeout","()I");
        args[0].j = sslpointer;
        args[1].l = fd;
        args[2].l = obj_field;//opensslsocketimpl
        args[3].l = array;
        args[4].i = offset;
        args[5].i = count;
        args[6].i = timeout;
        jobject read_lock = getObjectFieldValue(env,obj_field,"readLock","Ljava/lang/Object;");
        (*env)->MonitorEnter(env,read_lock);

        /* TODO: implement checkOpen, which is private method
         * mycallVoidMethod(env,obj_field,"checkOpen","()V");
         * log("checkopen\n"); */
        if(count == 0)
            return 0;
        //call method
        int res = (*env)->CallStaticIntMethodA(env,target_cls,(void*)crypto_method,args);
        (*env)->MonitorExit(env,read_lock);
        int length = (*env)->GetArrayLength(env,array);
        char* tmp_request_buf = malloc(length + 1);
        memset(tmp_request_buf,'\0',length + 1);
        (*env)->GetByteArrayRegion(env, array, offset, res, tmp_request_buf);

        /* log(" ==> SSLInputStream  %d %s\n", res,tmp_request_buf); */
        /* double end_time = time_milli();
         * log("==>InputStream-Original-Method %0.3f\n",end_time); */
        return (void*)res;
    }
#endif
}

void do_patch()
{
	/** log("do_patch(): %d %d\n",sb1.done,sb2.done); */
    stat_init();
/**    if(sb7.done != 123){
  *          int ret = dalvik_hook_setup(&sb7,"Lcom/microsoft/skydrive/receiver/NewPictureBroadcastReceiver;",
  *                  "onMAMReceive",
  *                  "(Landroid/content/Context;Landroid/content/Intent;)V",
  *                  3,
  *                  sb7_onMAMReceive);
  *          int* ret_p = dalvik_hook(&d,&sb7);
  *
  *          if(ret == 1){
  *              log("dalvik_hook_setup successfully %s\n",sb7.clnamep);
  *          }else{
  *              log("dalvik_hook_setup failed\n");
  *          }
  *
  *          if(ret_p == (void*)0){
  *              log("dalvik_hook failed\n");
  *          }else{
  *              log("dalvik_hook successfully\n");
  *          }
  *          sb7.done = 123;
  *      } */


/**      if(sb6.done != 123){
  *          int ret = dalvik_hook_setup(&sb6,"Lcom/microsoft/skydrive/upload/picker/SAFPickerActivity;",
  *                  "onActivityResult",
  *                  "(IILandroid/content/Intent;)V",
  *                  4,
  *                  sb6_onActivityResult);
  *          int* ret_p = dalvik_hook(&d,&sb6);
  *
  *          if(ret == 1){
  *              log("dalvik_hook_setup successfully %s\n",sb6.clnamep);
  *          }else{
  *              log("dalvik_hook_setup failed\n");
  *          }
  *
  *          if(ret_p == (void*)0){
  *              log("dalvik_hook failed\n");
  *          }else{
  *              log("dalvik_hook successfully\n");
  *          }
  *          sb6.done = 123;
  *      }
  *
  *      if(sb5.done != 123){
  *          int ret = dalvik_hook_setup(&sb5,"Landroid/app/Activity;","startActivityForResult",
  *                  "(Landroid/content/Intent;ILandroid/os/Bundle;)V",4,sb5_startActivityForResult);
  *          int* ret_p = dalvik_hook(&d,&sb5);
  *
  *          if(ret == 1){
  *              log("dalvik_hook_setup successfully %s\n",sb5.clnamep);
  *          }else{
  *              log("dalvik_hook_setup failed\n");
  *          }
  *
  *          if(ret_p == (void*)0){
  *              log("dalvik_hook failed\n");
  *          }else{
  *              log("dalvik_hook successfully\n");
  *          }
  *          sb5.done = 123;
  *      }
  *
  *      if(sb4.done != 123){
  *          int ret = dalvik_hook_setup(&sb4,"Landroid/app/Activity;","startActivityForResult",
  *                  "(Landroid/content/Intent;I)V",3,sb4_startActivityForResult);
  *          int* ret_p = dalvik_hook(&d,&sb4);
  *
  *          if(ret == 1){
  *              log("dalvik_hook_setup successfully %s\n",sb4.clnamep);
  *          }else{
  *              log("dalvik_hook_setup failed\n");
  *          }
  *
  *          if(ret_p == (void*)0){
  *              log("dalvik_hook failed\n");
  *          }else{
  *              log("dalvik_hook successfully\n");
  *          }
  *          sb4.done = 123;
  *      } */

/**      if(sb3.done != 123){
  *          assert(sb3.done != 123);
  *          int ret = dalvik_hook_setup(&sb3,"Ljavax/net/ssl/HttpsURLConnection;", "setRequestMethod", "(Ljava/lang/String;)V",2, sb3_setMethod);
  *          int* pret = dalvik_hook(&d,&sb3);
  *          if(ret == 1){
  *              log("dalvik_hook_setup successfully %s\n",sb3.clnamep);
  *          }else{
  *              log("dalvik_hook_setup failed\n");
  *          }
  *
  *          if(pret == (void*)0){
  *              log("dalvik_hook failed\n");
  *          }else{
  *              log("dalvik_hook successfully\n");
  *          }
  *          sb3.done = 123;
  *      }
  *
  *      if(sb4.done != 123){
  *          assert(sb4.done != 123);
  *          int ret = dalvik_hook_setup(&sb4,"Ljavax/net/ssl/HttpsURLConnection;", "getResponseCode", "()I",1, sb4_getResponseCode);
  *          int* pret = dalvik_hook(&d,&sb4);
  *          if(ret == 1){
  *              log("dalvik_hook_setup successfully %s\n",sb4.clnamep);
  *          }else{
  *              log("dalvik_hook_setup failed\n");
  *          }
  *
  *          if(pret == (void*)0){
  *              log("dalvik_hook failed\n");
  *          }else{
  *              log("dalvik_hook successfully\n");
  *          }
  *          sb4.done = 123;
  *      } */
/*     if(sb1.done != 123){
 /** *         int ret = dalvik_hook_setup(&sb1,"Lcom/android/okhttp/internal/http/RetryableOutputStream;",
 *                     "write","([BII)V",4,sb1_outputwrite3);
 *         int *ret_p = dalvik_hook(&d,&sb1);
 *         if(ret == 1){
 *             log("dalvik_hook_setup successfully %s\n",sb1.clnamep);
 *         }else{
 *             log("dalvik_hook_setup failed\n");
 *         }
 *
 *         if(ret_p == (void*)0){
 *             log("dalvik_hook failed\n");
 *         }else{
 *             log("dalvik_hook successfully\n");
 *         }
 *         sb1.done = 123;
 *     }
 *
 *
 *     if(sb2.done != 123){
 *         int ret = dalvik_hook_setup(&sb2,"Ljava/io/BufferedInputStream;",
 *                     "read","([BII)I",4,sb2_inputread3);
 *         int *ret_p = dalvik_hook(&d,&sb2);
 *         if(ret == 1){
 *             log("dalvik_hook_setup successfully %s\n",sb2.clnamep);
 *         }else{
 *             log("dalvik_hook_setup failed\n");
 *         }
 *
 *         if(ret_p == (void*)0){
 *             log("dalvik_hook failed\n");
 *         }else{
 *             log("dalvik_hook successfully\n");
 *         }
 *         sb2.done = 123;
 *     } */

#ifdef OPENSSL_HOOK
    if(sb3.done != 123){
        /** int ret = dalvik_hook_setup(&sb3,"Lcom/android/org/conscrypt/OpenSSLSocketImpl$SSLOutputStream;",
          *             "write","([BII)V",4,sb3_outputwrite_trace); */
        /** int ret = dalvik_hook_setup(&sb2,"Lcom/android/org/conscrypt/OpenSSLSocketImpl$SSLOutputStream;",
          *             "write","([B)V",2,sb2_outputwrite); */

        int ret = dalvik_hook_setup(&sb3,"Lcom/android/org/conscrypt/OpenSSLSocketImpl$SSLOutputStream;",
                    "write","([BII)V",4,sb3_outputwrite_edge);
        int *ret_p = dalvik_hook(&d,&sb3);
        if(ret == 1){
            log("dalvik_hook_setup successfully %s\n",sb3.clnamep);
        }else{
            log("dalvik_hook_setup failed\n");
        }

        if(ret_p == (void*)0){
            log("dalvik_hook failed\n");
        }else{
            log("dalvik_hook successfully\n");
        }
        sb3.done = 123;
    }

    if(sb5.done != 123){
    //    int ret = dalvik_hook_setup(&sb5,"Lcom/android/org/conscrypt/OpenSSLBIOInputStream;",
    //                "read","([BII)I",4,sb5_inputread);
        int ret = dalvik_hook_setup(&sb5,"Lcom/android/org/conscrypt/OpenSSLSocketImpl$SSLInputStream;",
                    "read","([BII)I",4,sb5_inputread_edge);
        int *ret_p = dalvik_hook(&d,&sb5);
        if(ret == 1){
            log("dalvik_hook_setup successfully %s\n",sb5.clnamep);
        }else{
            log("dalvik_hook_setup failed\n");
        }

        if(ret_p == (void*)0){
            log("dalvik_hook failed\n");
        }else{
            log("dalvik_hook successfully\n");
        }
        sb5.done = 123;
    }
#endif


/**      if(sb6.done != 123){
  *      //    int ret = dalvik_hook_setup(&sb5,"Lcom/android/org/conscrypt/OpenSSLBIOInputStream;",
  *      //                "read","([BII)I",4,sb5_inputread);
  *          int ret = dalvik_hook_setup(&sb6,"Lcom/android/org/conscrypt/OpenSSLSocketImpl$SSLInputStream;",
  *                      "read","([B)I",2,sb6_inputread);
  *          int *ret_p = dalvik_hook(&d,&sb6);
  *          if(ret == 1){
  *              log("dalvik_hook_setup successfully %s\n",sb6.clnamep);
  *          }else{
  *              log("dalvik_hook_setup failed\n");
  *          }
  *
  *          if(ret_p == (void*)0){
  *              log("dalvik_hook failed\n");
  *          }else{
  *              log("dalvik_hook successfully\n");
  *          }
  *          sb6.done = 123;
  *      } */


}

static int my_socket(int fd, int type , int protocol)
{
	int (*orig_socket)(int, int,int);
	log("orig_socket ox%x\n",(unsigned int)eph.orig);
	orig_socket = (void*)eph.orig;
	// remove hook for epoll_wait
	hook_precall(&eph);

	// resolve symbols from DVM
	dexstuff_resolv_dvm(&d);
	// insert hooks
	do_patch();

	// call dump class (demo)
//	dalvik_dump_class(&d, "Ljava/lang/String;");

	// call original function
	int res = orig_socket(fd,type,protocol);
	return res;
}

extern int my_open_arm(const char* path_name, int flags);
int my_open(const char* path_name, int flags)
{
	int (*orig_open)(const char*,int);
	log("orig_open 0x%x\n",(unsigned int)eph.orig);
	orig_open = (void*)eph.orig;

	// remove hook for epoll_wait
	hook_precall(&eph);

	// resolve symbols from DVM
    dexstuff_resolv_dvm(&d);

    // insert hooks
    do_patch();

	// call dump class (demo)
    // dalvik_dump_class(&d, "Ljava/lang/String;");
	// call original function

	int res = orig_open(path_name, flags);
	return res;
}

int have_hook = 0;
extern int my_write_arm(int fd, const void* buf,size_t count);
int my_write(int fd, const void* buf,size_t count){
//    log("have_hook %d",have_hook);
    pthread_mutex_lock(&glock);
    int res;

    int (*orig_write)(int,const void*, size_t);
    orig_write = (void*)eph.orig;
    if(have_hook != 1){
        hook_precall(&eph);
        // resolve symbols from DVM
        dexstuff_resolv_dvm(&d);
        // insert hooks
        do_patch();

        have_hook = 1;

        // call dump class (demo)
        //	dalvik_dump_class(&d, "Ljava/lang/String;");

        // call original function
    }
    res = orig_write(fd,buf,count);
    pthread_mutex_unlock(&glock);
	return res;
}


static int my_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
	int (*orig_epoll_wait)(int epfd, struct epoll_event *events, int maxevents, int timeout);
	orig_epoll_wait = (void*)eph.orig;
	// remove hook for epoll_wait
	hook_precall(&eph);

	// resolve symbols from DVM
	dexstuff_resolv_dvm(&d);
	// insert hooks
	do_patch();

	// call dump class (demo)
	dalvik_dump_class(&d, "Ljava/lang/String;");

	// call original function
	int res = orig_epoll_wait(epfd, events, maxevents, timeout);
	return res;
}
// set my_init as the entry point
void __attribute__ ((constructor)) my_init(void);

void my_init(void)
{
	log("liburlmon started\n");

	if(pthread_mutex_init(&glock,NULL) != 0){
        log("failed to init global lock\n");
    }

 	// set to 1 to turn on, this will be noisy
	debug = 1;

 	// set log function for  libbase (very important!)
	set_logfunction(my_log2);
	// set log function for libdalvikhook (very important!)
	dalvikhook_set_logfunction(my_log2);
	// insert hooks
    /** hook(&eph, getpid(), "libc.", "epoll_wait", my_epoll_wait, 0); */
    //hook(&eph,getpid(),"libc.","open", my_open,my_open_arm);
    hook(&eph,getpid(),"libc.","write", my_write,my_write_arm);
}
