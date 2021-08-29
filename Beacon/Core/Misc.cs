using System;
using System.IO;
using Beacon.Profiles;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Beacon.Utils;

namespace Beacon.Core
{
    /// <summary>
    /// 杂项
    /// </summary>
    class Misc
    {
        /// <summary>
        /// pwd
        /// </summary>
        public static byte[] GetCurrentDirectory()
        {
            return Bytes.FromString(Directory.GetCurrentDirectory());
        }

        /// <summary>
        /// cd
        /// </summary>
        public static void ChangeCurrentDirectory(byte[] DirectoryName)
        {
            Directory.SetCurrentDirectory(Bytes.ToString(DirectoryName));
        }

        /// <summary>
        /// sleep
        /// </summary>
        public static byte[] ChangeSleepTime(byte[] Buff)
        {
            byte[] pSleepTime = new byte[4];
            Array.Copy(Buff, 0, pSleepTime, 0, 4);                                      

            Array.Reverse(pSleepTime);
            uint nSleepTime = BitConverter.ToUInt32(pSleepTime, 0);
            Config._nSleepTime = (int)nSleepTime;

            return Bytes.FromString("ok");
        }

        /// <summary>
        /// Exit
        /// </summary>
        public static void Exit()
        {
            System.Environment.Exit(0);
        }

        /// <summary>
        /// 设置环境变量
        /// </summary>
        public static byte[] SetEnv(byte[] pEnv)
        {
            string[] sArray = Encoding.ASCII.GetString(pEnv).Split('=');
            System.Environment.SetEnvironmentVariable(sArray[0], sArray[1]);

            string strValue = Environment.GetEnvironmentVariable(sArray[0]);
            return Bytes.FromString(strValue+ "已设置");
        }

        /// <summary>
        /// 获得系统中各盘符
        /// </summary>
        public static byte[] GetDrives()
        {
            var drivers = DriveInfo.GetDrives();
            string sDrives ="";
            foreach (var driver in drivers)
            {
                if (driver.DriveType != DriveType.Fixed)
                {
                    continue;
                }
                sDrives += driver;
            }
            return Bytes.FromString(sDrives);
        }

        /// <summary>
        /// 返回错误信息给teamserver
        /// </summary>
        public static byte[] ErrorMsg(string Msg)
        {
            //byte[] pErrorMsg = new byte[Msg.Length + 12];
            //for (int i = 0; i < 12; i++) 
            //{
            //    pErrorMsg[i] = 0;
            //}
            //Array.Copy(pErrorMsg, 0, Bytes.FromString(Msg), 0, Msg.Length);
            return Bytes.FromString(Msg);
        }

    }
}
