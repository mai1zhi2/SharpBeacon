using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Beacon.Utils
{
    public class Bytes
    {
        public static byte[] FromString(string text)
        {
            return Encoding.UTF8.GetBytes(text);
        }

        public static byte[] FromBase64(string base64Text)
        {
            return Convert.FromBase64String(base64Text);
        }

        public static string ToString(byte[] bytes)
        {
            return Encoding.UTF8.GetString(bytes);
        }

        public static string ToBase64(byte[] bytes)
        {
            return Convert.ToBase64String(bytes);
        }

        public static string ToHex(byte[] bytes)
        {
            var builder = new StringBuilder();
            foreach (var b in bytes)
            {
                builder.AppendFormat("{0:X2}", b);
            }
            return builder.ToString();
        }

        public static byte[] Combine(params byte[][] arrays)
        {
            var result = new byte[arrays.Sum(a => a.Length)];

            var offset = 0;

            foreach (var array in arrays)
            {
                Buffer.BlockCopy(array, 0, result, offset, array.Length);
                offset += array.Length;
            }

            return result;
        }

        public static bool Is64Bit
        {
            get { return IntPtr.Size == 8; }
        }


        public static int FindBytes(byte[] src, byte[] find)
        {
            int index = -1;
            int matchIndex = 0;
            // handle the complete source array
            for (int i = 0; i < src.Length; i++)
            {
                if (src[i] == find[matchIndex])
                {
                    if (matchIndex == (find.Length - 1))
                    {
                        index = i - matchIndex;
                        break;
                    }
                    matchIndex++;
                }
                else if (src[i] == find[0])
                {
                    matchIndex = 1;
                }
                else
                {
                    matchIndex = 0;
                }

            }
            return index;
        }

        public static byte[] ReplaceBytes2(byte[] src, byte[] search, byte[] repl)
        {
            byte[] dst = null;
            int index = FindBytes(src, search);//indx < srclen继续Find
            if (index >= 0)
            {
                dst = new byte[src.Length - search.Length ];
                // before found array
                Buffer.BlockCopy(src, 0, dst, 0, index);
                // repl copy
                //Buffer.BlockCopy(repl, 0, dst, index, repl.Length);
                // rest of src array
                Buffer.BlockCopy(
                    src,
                    index + search.Length,
                    dst,
                    index ,
                    src.Length - (index + search.Length));
            }
            return dst;
        }

        public static byte[] ReplaceBytes(byte[] src, byte[] search, byte[] repl)
        {
            byte[] dst = null;
            byte[] temp = null;
            int index = FindBytes(src, search);
           // index += 8;
            while (index >= 0)
            {
                if (temp == null)
                    temp = src;
                else
                    temp = dst;

                dst = new byte[temp.Length - search.Length -8];

                // before found array
                Buffer.BlockCopy(temp, 0, dst, 0, index -8);
                // repl copy
                //Buffer.BlockCopy(repl, 0, dst, index, repl.Length);
                // rest of src array
                Buffer.BlockCopy(
                    temp,
                    index + search.Length,
                    dst,
                    index -8 ,
                    temp.Length - (index + search.Length));//260096

                index = FindBytes(dst, search);
                //index += 8;
            }
            if (index <  0 && dst == null) { return src; }
            return dst;
        }
    }
}
