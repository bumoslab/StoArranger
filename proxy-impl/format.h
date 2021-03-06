#ifndef __FORMAT_H__
#define __FORMAT_H_


#define SESSIONID_SIZE 66
const int od_fmtreq2_length = 1089;

const char* onesync_rsp1 =
"HTTP/1.1 200 OK\r\n"
"Cache-Control: private, no-cache, no-store, must-revalidate\r\n"
"Content-Length: 391\r\n"
"Content-Type: application/json; charset=UTF-8\r\n"
"Server: Live-API/19.39.406.4005 Microsoft-HTTPAPI/2.0\r\n"
"P3P: CP=\"BUS CUR CONo FIN IVDo ONL OUR PHY SAMo TELo\"\r\n"
"X-MSNSERVER: SN3302____PAP164\r\n"
"Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n"
"X-Content-Type-Options: nosniff\r\n"
"X-HTTP-Live-Request-Id: API.6af2ed2d-255f-460a-abee-900a304bf009\r\n"
"X-AsmVersion: UNKNOWN; 19.39.0.0\r\n"
"Date: Wed, 04 May 2016 01:48:44 GMT\r\n\r\n"
"{\015   \"id\": \"42a638c59aa1eaa8\", \015   \"name\": \"mos wang\", \015   \"first_name\": \"mos\", \015   \"last_name\": \"wang\", \015   \"link\": \"https://profile.live.com/\", \015   \"gender\": null, \015   \"emails\": {\015      \"preferred\": \"andmoslab@gmail.com\", \015      \"account\": \"andmoslab@gmail.com\", \015      \"personal\": null, \015      \"business\": null\015   }, \015   \"locale\": \"en_US\", \015   \"updated_time\": \"2016-05-01T23:14:34+000\" \015}";

const char* onesync_rsp2 =
"HTTP/1.1 200 OK\r\n"
"Cache-Control: private, no-cache, no-store, must-revalidate\r\n"
"Content-Length: 57\r\n"
"Content-Type: application/json; charset=UTF-8\r\n"
"Server: Live-API/19.39.406.4005 Microsoft-HTTPAPI/2.0\r\n"
"P3P: CP=\"BUS CUR CONo FIN IVDo ONL OUR PHY SAMo TELo\"\r\n"
"X-MSNSERVER: SN3302____PAP164\r\n"
"Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n"
"X-Content-Type-Options: nosniff\r\n"
"X-HTTP-Live-Request-Id: API.8375ec1f-b1c7-4696-8ffb-1263c5b931ef\r\n"
"X-AsmVersion: UNKNOWN; 19.39.0.0\r\n"
"Date: Wed, 04 May 2016 01:48:45 GMT\r\n\r\n"
"{\015   \"quota\": 32212254720, \015   \"available\": 32212102985\015}";

const char* onesync_rsp3 =
"HTTP/1.1 200 OK\r\n"
"Cache-Control: private, no-cache, no-store, must-revalidate\r\n"
"Content-Length: olength\r\n"
"Content-Type: application/json; charset=UTF-8\r\n"
"Server: Live-API/19.39.406.4005 Microsoft-HTTPAPI/2.0\r\n"
"P3P: CP=\"BUS CUR CONo FIN IVDo ONL OUR PHY SAMo TELo\"\r\n"
"X-MSNSERVER: SN3302____PAP164\r\n"
"Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n"
"X-Content-Type-Options: nosniff\r\n"
"X-HTTP-Live-Request-Id: API.8375ec1f-b1c7-4696-8ffb-1263c5b931ef\r\n"
"X-AsmVersion: UNKNOWN; 19.39.0.0\r\n"
"Date: Wed, 04 May 2016 01:48:45 GMT\r\n\r\n";



const char* onesync_content_rsp1 =
    "HTTP/1.1 302 Found\r\n"
    "Cache-Control: private, no-cache, no-store, must-revalidate\r\n"
    "Content-Length: 0\r\n"
    "Location: ";
    /*
    "Location: https://gnkk8a-bn1306.files.1drv.com/y3mbGUBLvNR9-bpV6mc0YAQdvsKvoEbkmMSpM9M6VXk-KXYV7mqRWwswR_7oTJRN9EopekQKoa9O1LZ2q4QLJ0Y3toHksn1NzW6KqJsRWVeF7TT6yBmRDghHs7ajq4q4Q2LHITSbiU8ef3MUJC2eG2_8OZCwmG3Sd7vUAm5jYZkK6k/f-1-8?psid=1\r\n"
    */
const char* onesync_content_rsp2 =
    "Server: Live-API/19.48.723.4015 Microsoft-HTTPAPI/2.0\r\n"
    "P3P: CP=\"BUS CUR CONo FIN IVDo ONL OUR PHY SAMo TELo\"\r\n"
    "X-MSNSERVER: CH3302____PAP030\r\n"
    "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n"
    "X-Content-Type-Options: nosniff\r\n"
    "X-HTTP-Live-Request-Id: API.bc44e108-5726-4387-9016-d4aaaa77badc\r\n"
    "X-AsmVersion: UNKNOWN; 19.48.0.0\r\n"
    "Date: Thu, 25 Aug 2016 18:15:20 GMT\r\n\r\n";


char * response1 =
    "HTTP/1.1 201 Created\r\n"
    "Content-Length: 0\r\n"
    "Server: Microsoft-HTTPAPI/2.0\r\n"
    "P3P: CP=\"BUS CUR CONo FIN IVDo ONL OUR PHY SAMo TELo\"\r\n"
    "X-MSNSERVER: BN1306____PAP301\r\n"
    "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n"
    "BITS-Packet-Type: Ack\r\n"
    "BITS-Protocol: {7df0354d-249b-430f-820d-3d2a9bef4931}\r\n"
    "BITS-Session-Id: 3mkUBqDcMuyQXuCN3ezkTTYm9yKSjrmOYyB0FuP2FdoCmi_yBQWI0ja1eTIfRBlYVZ\r\n"
    "Accept-Encoding: Identity\r\n"
    "X-AsmVersion: UNKNOWN; 19.31.0.0\r\n"
    "Date: Wed, 11 Nov 2015 11:20:41 GMT\r\r\n\n";
char * response2 =
    "HTTP/1.1 200 OK\r\n"
    "Content-Length: 0\r\n"
    "Server: Microsoft-HTTPAPI/2.0\r\n"
    "P3P: CP=\"BUS CUR CONo FIN IVDo ONL OUR PHY SAMo TELo\"\r\n"
    "X-MSNSERVER: BN1306____PAP301\r\n"
    "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n"
    "BITS-Packet-Type: Ack\r\n"
    "BITS-Session-Id: 3mkUBqDcMuyQXuCN3ezkTTYm9yKSjrmOYyB0FuP2FdoCmi_yBQWI0ja1eTIfRBlYVZ\r\n"
    "BITS-Received-Content-Range: 3356\r\n"
    "X-AsmVersion: UNKNOWN; 19.32.0.0\r\n"
    "Date: Fri, 13 Nov 2015 02:18:52 GMT\r\n\r\n";
char * response3 =
    "HTTP/1.1 200 OK\r\n"
    "Content-Length: 0\r\n"
    "Content-Location: https://public-bn1306.files.1drv.com/y3pUkaxJMAq2sekOUiiWcuV8Yfj8YIo49eTYndfaxH9UdKpze6pmblF2ZIHVqwUBmBuJ9diyxBb_Sc61I3khnre3I4kbpNSUZ5mUSh_oMEVudI\r\n"
    "Server: Microsoft-HTTPAPI/2.0\r\n"
    "P3P: CP=\"BUS CUR CONo FIN IVDo ONL OUR PHY SAMo TELo\"\r\n"
    "X-MSNSERVER: BN1306____PAP281\r\n"
    "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n"
    "BITS-Packet-Type: Ack\r\n"
    "X-Resource-Id: 42A638C59AA1EAA8!277\r\n"
    "X-Cid: 4802588473991228072\r\n"
    "X-Last-Modified-ISO8601: 2015-11-13T02:18:54.413Z\r\n"
    "X-ItemVersion: 0\r\n"
    "Etag: 42A638C59AA1EAA8!277.0\r\n"
    "X-AsmVersion: UNKNOWN; 19.32.0.0\r\n"
    "Date: Fri, 13 Nov 2015 02:18:54 GMT\r\n\r\n";

char * response4 =
    "HTTP/1.1 200 OK\r\n"
    "Access-Control-Allow-Origin: *\r\n"
    "Content-Type: application/json; charset=utf-8\r\n"
    "Date: Fri, 20 Nov 2015 04:45:10 GMT\r\n"
    "Server: openresty/1.7.7.2\r\n"
    "X-Content-Type-Options: nosniff\r\n"
    "X-Powered-By: Express\r\n"
    "Content-Length: 2\r\n"
    "Connection: keep-alive\r\n\r\n";

    const char * fmtId = "BITS-Session-Id: ";
    const char * fmtAcpt = "Accept-Encoding: ";
    const char * demoId = "3mkUBqDcMuyQXuCN3ezkTTYm9yKSjrmOYyB0FuP2FdoCmi_yBQWI0ja1eTIfRBlYVZ";
    const char * fmtreq1 = "BITS-Packet-Type: Create-Session";
    const char * fmtreq2 = "BITS-Packet-Type: Fragment";
    const char * fmtreq3 = "BITS-Packet-Type: Close-Session";
    const char * SESSIONID_FORMAT = "BITS-Session-Id: ";
    const char * SERVERID_FORMAT = "X-MSNSERVER: ";

#define GOOGLE_DR_ID_SIZE 16
#define GOOGLE_DR_UPLOADER_ID_SIZE 98
#define GOOGLE_DR_ETAG_SIZE0 18
#define GOOGLE_DR_ETAG_SIZE1 27
#define GOOGLE_DR_ETAG_PREFIX_SIZE 27
    const char *gdriveReq0 = "GET /drive/v2internal/files/";
    const char *gdriveReq1 = "POST /upload/drive/v2/files?uploadType=resumable HTTP/1.1";
    const char *gdriveReq2 = "PUT /upload/drive/v2/files?uploadType=resumable&upload_id=";
    const char *gdriveReq3 = "GET /feeds/default/private/full/document%";
    const char *ETAG_SAMPLE0 = "amKkzAMv_fUBF0Cxt1a1WaLm5Nk/MTQ0ODQxOTAyMjk2OA";
//    const char *ETAG_SAMPLE1 = "amKkzAMv_fUBF0Cxt1a1WaLm5Nk/aTLaEKfqDjxmIFcmTI0DGsYJ9_M";
    const char *ETAG_SAMPLE1 = "jbXGz7mn3P-4yQwb7qfM1aCupRQ/DCj0BKZcVfA5aZfqhyCuK-E-nd4";


    const char* uploadID_Sample = "AEnB2Up2ao2-uhfOFLDeVXUlyehoncRb9TRRmbyDtF5nCEEJsU56Iv1-Y3tu8KMpYBSgc8bAg-YliLWB_4444vvMYYbbow7O7w";

    const char *gdriveRsp0 =
    "HTTP/1.1 200 OK\r\n"
    "Expires: Sun, 18 Apr 2016 21:02:40 GMT\r\n"
    "Date: Sun, 18 Apr 2016 21:02:40 GMT\r\n"
    "Cache-Control: private, max-age=0, must-revalidate, no-transform\r\n"
    "ETag: \"jbXGz7mn3P-4yQwb7qfM1aCupRQ/DCj0BKZcVfA5aZfqhyCuK-E-nd4\"\r\n"
    "Vary: Origin\r\n"
    "Vary: X-Origin\r\n"
    "Content-Type: application/json; charset=UTF-8\r\n"
    "Content-Encoding: gzip\r\n"
    "X-Content-Type-Options: nosniff\r\n"
    "X-Frame-Options: SAMEORIGIN\r\n"
    "X-XSS-Protection: 1; mode=block\r\n"
    "Server: GSE\r\n"
    "Alternate-Protocol: 443:quic\r\n"
    "Alt-Svc: quic=\":443\"; ma=2592000; v=\"32,31,30,29,28,27,26,25\"\r\n"
    "Transfer-Encoding: chunked\r\n\r\n";
#if 0
    "{\n"
    " \"kind\": \"drive#generatedIds\",\n"
    " \"space\": \"drive\",\n"
    " \"ids\": [\n"
    "  \"0BzCkQYBmdM-2SjVfWlFYZ1RtdUU\"\n"
    " ]\n"
    "}\012";
#endif
    const char *gdriveRsp1 =
    "HTTP/1.1 200 OK\r\n"
    "X-GUploader-UploadID: AEnB2Up2ao2-uhfOFLDeVXUlyehoncRb9TRRmbyDtF5nCEEJsU56Iv1-Y3tu8KMpYBSgc8bAg-YliLWB_4444vvMYYbbow7O7w\r\n"
//    "X-GUploader-UploadID: AEnB2UqJazKMEVY7RWoiY-38rw1rWa2bg-QJLNuI2vmpSs3HcuetBnTxInrbnnmm8BrhGmJ56ap3z4Jhk9wyohf7iNavGDX3Aw\r\n"
    //"Location: https://www.googleapis.com/upload/drive/v2/files?uploadType=resumable&upload_id=AEnB2UqJazKMEVY7RWoiY-38rw1rWa2bg-QJLNuI2vmpSs3HcuetBnTxInrbnnmm8BrhGmJ56ap3z4Jhk9wyohf7iNavGDX3Aw\r\n"
    "Location: https://www.googleapis.com/upload/drive/v2/files?uploadType=resumable&upload_id=AEnB2Up2ao2-uhfOFLDeVXUlyehoncRb9TRRmbyDtF5nCEEJsU56Iv1-Y3tu8KMpYBSgc8bAg-YliLWB_4444vvMYYbbow7O7w\r\n"
    "ETag: \"fbeGFVkCD3tGFpdjp1CYyuwDABw/A7u6rz5JrOJoRFZRWlU84L7TPC4\"\r\n"
    "Vary: Origin\r\n"
    "Vary: X-Origin\r\n"
    "Cache-Control: no-cache, no-store, max-age=0, must-revalidate\r\n"
    "Pragma: no-cache\r\n"
    "Expires: Fri, 01 Jan 1990 00:00:00 GMT\r\n"
    "Date: Wed, 25 Nov 2015 02:37:02 GMT\r\n"
    "Content-Length: 0\r\n"
    "Server: UploadServer\r\n"
    "Content-Type: text/html; charset=UTF-8\r\n"
    "Alternate-Protocol: 443:quic,p=0\r\n"
    //"Alt-Svc: quic=\":443\"; ma=604800; v=\"30,29,28,27,26,25\"\r\n\r\n";
    "Alt-Svc: clear\r\n\r\n";

    char* gdriveRsp2 =
    "HTTP/1.1 200 OK\r\n"
    "X-GUploader-UploadID: AEnB2Up2ao2-uhfOFLDeVXUlyehoncRb9TRRmbyDtF5nCEEJsU56Iv1-Y3tu8KMpYBSgc8bAg-YliLWB_4444vvMYYbbow7O7w\r\n"
    "ETag: \"fbeGFVkCD3tGFpdjp1CYyuwDABw/MTQ0ODQxOTAyMjk2OA\"\r\n"
    "Vary: Origin\r\n"
    "Vary: X-Origin\r\n"
    "Content-Type: application/json; charset=UTF-8\r\n"
    "Cache-Control: no-cache, no-store, max-age=0, must-revalidate\r\n"
    "Pragma: no-cache\r\n"
    "Expires: Fri, 01 Jan 1990 00:00:00 GMT\r\n"
    "Date: Wed, 25 Nov 2015 02:37:03 GMT\r\n"
    "Content-Length: 2642\r\n"
    "Server: UploadServer\r\n"
    "Alternate-Protocol: 443:quic,p=0\r\n"
   // "Alt-Svc: quic=\":443\"; ma=604800; v=\"30,29,28,27,26,25\"\015\012\015\012"
    "Alt-Svc: clear\r\n\r\n"
    "{\n"
    " \"kind\": \"drive#file\",\n"
    " \"id\": \"0BzCkQYBmdM-2SjVfWlFYZ1RtdUU\",\n"
    " \"etag\": \"\\\"fbeGFVkCD3tGFpdjp1CYyuwDABw/MTQ0ODQxOTAyMjk2OA\\\"\",\n"
    " \"selfLink\": \"https://www.googleapis.com/drive/v2/files/0BzCkQYBmdM-2SjVfWlFYZ1RtdUU\",\n"
    " \"webContentLink\": \"https://docs.google.com/uc?id=0BzCkQYBmdM-2SjVfWlFYZ1RtdUU&export=download\",\n"
    " \"alternateLink\": \"https://drive.google.com/file/d/0BzCkQYBmdM-2SjVfWlFYZ1RtdUU/view?usp=drivesdk\",\n"
    " \"iconLink\": \"https://ssl.gstatic.com/docs/doclist/images/generic_app_icon_16.png\",\n"
    " \"title\": \"ca.crt\",\n"
    " \"mimeType\": \"application/x-x509-server-cert\",\n"
    " \"labels\": {\n"
    "  \"starred\": false,\n"
    "  \"hidden\": false,\n"
    "  \"trashed\": false,\n"
    "  \"restricted\": false,\n"
    "  \"viewed\": true\n"
    " },\n"
    " \"createdDate\": \"2015-11-25T02:37:02.968Z\",\n"
    " \"modifiedDate\": \"2015-11-25T02:37:02.968Z\",\n"
    " \"modifiedByMeDate\": \"2015-11-25T02:37:02.968Z\",\n"
    " \"lastViewedByMeDate\": \"2015-11-25T02:37:02.968Z\",\n"
    " \"markedViewedByMeDate\": \"1970-01-01T00:00:00.000Z\",\n"
    " \"version\": \"2881\",\n"
    " \"parents\": [\n"
    "  {\n"
    "   \"kind\": \"drive#parentReference\",\n"
    "   \"id\": \"0ADCkQYBmdM-2Uk9PVA\",\n"
    "   \"selfLink\": \"https://www.googleapis.com/drive/v2/files/0BzCkQYBmdM-2SjVfWlFYZ1RtdUU/parents/0ADCkQYBmdM-2Uk9PVA\",\n"
    "   \"parentLink\": \"https://www.googleapis.com/drive/v2/files/0ADCkQYBmdM-2Uk9PVA\",\n"
    "   \"isRoot\": true\n"
    "  }\n"
    " ],\n"
    " \"downloadUrl\": \"https://doc-0k-3g-docs.googleusercontent.com/docs/securesc/f1j9mtso1c51h24m28j6mu8tk1njqvta/fnggfir5pv5560evn9emhpui6h06ur4d/1448416800000/09500111083742506579/09500111083742506579/0BzCkQYBmdM-2SjVfWlFYZ1RtdUU?e=download&gd=true\",\n"
    " \"userPermission\": {\n"
    "  \"kind\": \"drive#permission\",\n"
    "  \"etag\": \"\\\"fbeGFVkCD3tGFpdjp1CYyuwDABw/aTLaEKfqDjxmIFcmTI0DGsYJ9_M\\\"\",\n"
    "  \"id\": \"me\",\n"
    "  \"selfLink\": \"https://www.googleapis.com/drive/v2/files/0BzCkQYBmdM-2SjVfWlFYZ1RtdUU/permissions/me\",\n"
    "  \"role\": \"owner\",\n"
    "  \"type\": \"user\"\n"
    " },\n"
    " \"originalFilename\": \"ca.crt\",\n"
    " \"fileExtension\": \"crt\",\n"
    " \"md5Checksum\": \"b052b9da9075339cfaa4553e227fc891\",\n"
    " \"fileSize\": \"1919\",\n"
    " \"quotaBytesUsed\": \"1919\",\n"
    " \"ownerNames\": [\n"
    "  \"Test Test\"\n"
    " ],\n"
    " \"owners\": [\n"
    "  {\n"
    "   \"kind\": \"drive#user\",\n"
    "   \"displayName\": \"Test Test\",\n"
    "   \"isAuthenticatedUser\": true,\n"
    "   \"permissionId\": \"09500111083742506579\",\n"
    "   \"emailAddress\": \"andmoslab@gmail.com\"\n"
    "  }\n"
    " ],\n"
    " \"lastModifyingUserName\": \"Test Test\",\n"
    " \"lastModifyingUser\": {\n"
    "  \"kind\": \"drive#user\",\n"
    "  \"displayName\": \"Test Test\",\n"
    "  \"isAuthenticatedUser\": true,\n"
    "  \"permissionId\": \"09500111083742506579\",\n"
    "  \"emailAddress\": \"andmoslab@gmail.com\"\n"
    " },\n"
    " \"editable\": true,\n"
    " \"copyable\": true,\n"
    " \"writersCanShare\": true,\n"
    " \"shared\": false,\n"
    " \"explicitlyTrashed\": false,\n"
    " \"appDataContents\": false,\n"
    " \"headRevisionId\": \"0BzCkQYBmdM-2M2hBbHFmMTF6ZXppRmhEcHhodzB1VmxvenUwPQ\",\n"
    " \"spaces\": [\n"
    "  \"drive\"\n"
    " ]\n"
    "}\012";

    char * gdriveRsp3_Part1 =
    "HTTP/1.1 308 Resume Incomplete\r\n"
//    "X-GUploader-UploadID: AEnB2UqJazKMEVY7RWoiY-38rw1rWa2bg-QJLNuI2vmpSs3HcuetBnTxInrbnnmm8BrhGmJ56ap3z4Jhk9wyohf7iNavGDX3Aw\r\n"
    "X-GUploader-UploadID: AEnB2Up2ao2-uhfOFLDeVXUlyehoncRb9TRRmbyDtF5nCEEJsU56Iv1-Y3tu8KMpYBSgc8bAg-YliLWB_4444vvMYYbbow7O7w\r\n";
#if 0
    "Range: bytes=0-262143\r\n"
    "X-Range-MD5: ec87a838931d4d5d2e94a04644788a55\r\n"
#endif
    char * gdriveRsp3_Part2 =
    "Content-Length: 0\r\n"
    "Date: Thu, 03 Dec 2015 20:42:35 GMT\r\n"
    "Server: UploadServer\r\n"
    "Content-Type: text/html; charset=UTF-8\r\n"
    "Alternate-Protocol: 443:quic,p=1\r\n"
    "Alt-Svc: quic=\":443\"; ma=604800; v=\"30,29,28,27,26,25\"\r\n\r\n";

    char * gdriveRsp3 =
    "HTTP/1.1 308 Resume Incomplete\r\n"
//    "X-GUploader-UploadID: AEnB2UqJazKMEVY7RWoiY-38rw1rWa2bg-QJLNuI2vmpSs3HcuetBnTxInrbnnmm8BrhGmJ56ap3z4Jhk9wyohf7iNavGDX3Aw\r\n"
    "X-GUploader-UploadID: AEnB2Up2ao2-uhfOFLDeVXUlyehoncRb9TRRmbyDtF5nCEEJsU56Iv1-Y3tu8KMpYBSgc8bAg-YliLWB_4444vvMYYbbow7O7w\r\n"
    "Range: bytes=0-262143\r\n"
    "X-Range-MD5: ec87a838931d4d5d2e94a04644788a55\r\n"
    "Content-Length: 0\r\n"
    "Date: Thu, 03 Dec 2015 20:42:35 GMT\r\n"
    "Server: UploadServer\r\n"
    "Content-Type: text/html; charset=UTF-8\r\n"
    "Alternate-Protocol: 443:quic,p=1\r\n"
    "Alt-Svc: quic=\":443\"; ma=604800; v=\"30,29,28,27,26,25\"\r\n\r\n";

    char *gdriveRsp4 =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: application/atom+xml; charset=UTF-8; type=entry\r\n"
    "Expires: Sun, 06 Dec 2015 23:11:18 GMT\r\n"
    "Date: Sun, 06 Dec 2015 23:11:18 GMT\r\n"
    "Cache-Control: private, max-age=0, must-revalidate\r\n"
    "Vary: Accept, X-GData-Authorization, GData-Version\r\n"
    "GData-Version: 3.0\r\n"
    "ETag: \"AVBWGExfGCt7ImBl\"\r\n"
    "Last-Modified: Sun, 06 Dec 2015 23:11:18 GMT\r\n"
    "Content-Encoding: gzip\r\n"
    "X-Content-Type-Options: nosniff\r\n"
    "X-Frame-Options: SAMEORIGIN\r\n"
    "X-XSS-Protection: 1; mode=block\r\n"
    "Server: GSE\r\n"
    "Alternate-Protocol: 443:quic,p=0\r\n"
    "Alt-Svc: clear\r\n"
    "Transfer-Encoding: chunked\r\n\r\n";

#if 0

    char *gdriveRsp2 =
    "HTTP/1.1 200 OK\r\n"
    "X-GUploader-UploadID: AEnB2Up2ao2-uhfOFLDeVXUlyehoncRb9TRRmbyDtF5nCEEJsU56Iv1-Y3tu8KMpYBSgc8bAg-YliLWB_P6o2vvMYYbbow7O7w\r\n"
    "ETag: \"fbeGFVkCD3tGFpdjp1CYyuwDABw/MTQ0ODQxOTAyMjk2OA\"\r\n"
    "Vary: Origin\r\n"
    "Vary: X-Origin\r\n"
    "Content-Type: application/json; charset=UTF-8\r\n"
    "Cache-Control: no-cache, no-store, max-age=0, must-revalidate\r\n"
    "Pragma: no-cache\r\n"
    "Expires: Fri, 01 Jan 1990 00:00:00 GMT\r\n"
    "Date: Wed, 25 Nov 2015 02:37:03 GMT\r\n"
    "Content-Length: 2642\r\n"
    "Server: UploadServer\r\n"
    "Alternate-Protocol: 443:quic,p=1\r\n"
    "Alt-Svc: quic=\":443\"; ma=604800; v=\"30,29,28,27,26,25\"\r\n\r\n"
    "{\n"
    " \"kind\": \"drive#file\",\n"
    " \"id\": \"0BzCkQYBmdM-2T1ZVX3RjVFNDZW8\",\n"
    " \"etag\": \"\\\"fbeGFVkCD3tGFpdjp1CYyuwDABw/MTQ0ODQxOTAyMjk2OA\\\"\",\n"
    " \"selfLink\": \"https://www.googleapis.com/drive/v2/files/0BzCkQYBmdM-2T1ZVX3RjVFNDZW8\",\n"
    " \"webContentLink\": \"https://docs.google.com/uc?id=0BzCkQYBmdM-2T1ZVX3RjVFNDZW8&export=download\",\n"
    " \"alternateLink\": \"https://drive.google.com/file/d/0BzCkQYBmdM-2T1ZVX3RjVFNDZW8/view?usp=drivesdk\",\n"
    " \"iconLink\": \"https://ssl.gstatic.com/docs/doclist/images/generic_app_icon_16.png\",\n"
    " \"title\": \"ca.key\",\n"
    " \"mimeType\": \"application/pgp-keys\",\n"
    " \"labels\": {\n"
    "  \"starred\": false,\n"
    "  \"hidden\": false,\n"
    "  \"trashed\": false,\n"
    "  \"restricted\": false,\n"
    "  \"viewed\": true\n"
    " },\n"
    " \"createdDate\": \"2015-11-25T02:38:12.449Z\",\n"
    " \"modifiedDate\": \"2015-11-25T02:38:12.449Z\",\n"
    " \"modifiedByMeDate\": \"2015-11-25T02:38:12.449Z\",\n"
    " \"lastViewedByMeDbY5Oz8U\": \"2015-11-25T02:38:12.449Z\",\n"
    " \"markedViewedByMeDate\": \"1970-01-01T00:00:00.000Z\",\n"
    " \"version\": \"2884\",\n"
    " \"parents\": [\n"
    "  {\n"
    "  \"kind\": \"drive#parentReference\",\n"
    "  \"id\": \"0ADCkQYBmdM-2Uk9PVA\",\n"
    "  \"selfLink\": \"https://www.googleapis.com/drive/v2/files/0BzCkQYBmdM-2T1ZVX3RjVFNDZW8/parents/0ADCkQYBmdM-2Uk9PVA\",\n"
    "  \"parentLink\": \"https://www.googleapis.com/drive/v2/files/0ADCkQYBmdM-2Uk9PVA\",\n"
    "  \"isRoot\": true\n"
    "  }\n"
    " ],\n"
    " \"downloadUrl\": \"https://doc-14-3g-docs.googleusercontent.com/docs/securesc/f1j9mtso1c51h24m28j6mu8tk1njqvta/dr0i1jp9ha76inq2c8mqk1ieg4dgpqko/1448416800000/09500111083742506579/09500111083742506579/0BzCkQYBmdM-2T1ZVX3RjVFNDZW8?e=download&gd=true\",\n"
    " \"userPermission\": {\n"
    "  \"kind\": \"drive#permission\",\n"
    "  \"etag\": \"\\\"fbeGFVkCD3tGFpdjp1CYyuwDABw/W0qez6ouupVbHO5iPMeMo1IvTNA\\\"\",\n"
    "  \"id\": \"me\",\n"
    "  \"selfLink\": \"https://www.googleapis.com/drive/v2/files/0BzCkQYBmdM-2T1ZVX3RjVFNDZW8/permissions/me\",\n"
    "  \"role\": \"owner\",\n"
    "  \"type\": \"user\"\n"
    " },\n"
    " \"originalFilename\": \"ca.key\",\n"
    " \"fileExtension\": \"key\",\n"
    " \"md5Checksum\": \"e96c58b5ee4c3ae65c96e6bb3c92b300\",\n"
    " \"fileSize\": \"3247\",\n"
    " \"quotaBytesUsed\": \"3247\",\n"
    " \"ownerNames\": [\n"
    " \"Test Test\"\n"
    " ],\n"
    " \"owners\": [\n"
    "  {\n"
    "  \"kind\": \"drive#user\",\n"
    "  \"displayName\": \"Test Test\",\n"
    "  \"isAuthenticatedUser\": true,\n"
    "  \"permissionId\": \"09500111083742506579\",\n"
    "  \"emailAddress\": \"andmoslab@gmail.com\"\n"
    "  }\n"
    " ],\n"
    " \"lastModifyingUserName\": \"Test Test\",\n"
    " \"lastModifyingUser\": {\n"
    "  \"kind\": \"drive#user\",\n"
    "  \"displayName\": \"Test Test\",\n"
    "  \"isAuthenticatedUser\": true,\n"
    "  \"permissionId\": \"09500111083742506579\",\n"
    "  \"emailAddress\": \"andmoslab@gmail.com\"\n"
    " },\n"
    " \"editable\": true,\n"
    " \"copyable\": true,\n"
    " \"writersCanShare\": true,\n"
    " \"shared\": false,\n"
    " \"explicitlyTrashed\": false,\n"
    " \"appDataContents\": false,\n"
    " \"headRevisionId\": \"0BzCkQYBmdM-2SkZHTzZWOXVISVhhcXYxczdFcmR4V3RGcnJrPQ\",\n"
    " \"spaces\": [\n"
    "  \"drive\"\n"
    " ]\n"
    "}\r\n\r\n";
#endif


#endif
