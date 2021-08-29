using System;
using Reflect = System.Reflection;

namespace Stager
{
    /// <summary>
    /// 执行下载后在内存中的程序集
    /// </summary>
    class Assembly
    {
        /// <summary>
        /// 执行下载后在内存中的程序集数据
        /// </summary>
        /// <param name="AssemblyBytes">内存中的程序集数据</param>
        /// <param name="Args">程序集所需参数</param>
        public static void AssemblyExecute(byte[] AssemblyBytes, Object[] Args = null)
        {
            if (Args == null)
            {
                Args = new Object[] { new string[] { } };
            }
            Reflect.Assembly assembly = Load(AssemblyBytes);
            assembly.EntryPoint.Invoke(null, Args);
        }

        /// <summary>
        /// 执行下载后在内存中的程序集数据
        /// </summary>
        /// <param name="EncodedAssembly">内存中被编码的程序集数据</param>
        /// <param name="Args">程序集所需参数</param>
        public static void AssemblyExecute(String EncodedAssembly, Object[] Args = default(Object[]))
        {
            AssemblyExecute(Convert.FromBase64String(EncodedAssembly), Args);
        }

        /// <summary>
        /// 执行下载后在内存中的程序集
        /// </summary>
        /// <param name="EncodedAssembly">内存中程序集数据</param>
        public static Reflect.Assembly Load(byte[] AssemblyBytes)
        {
            return Reflect.Assembly.Load(AssemblyBytes);
        }

        public static Reflect.Assembly Load(string EncodedAssembly)
        {
            //return Reflect.Assembly.Load(Convert.FromBase64String(EncodedAssembly));
            return Reflect.Assembly.Load(EncodedAssembly);
        }
    }
}
