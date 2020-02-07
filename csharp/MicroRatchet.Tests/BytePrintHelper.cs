using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace MicroRatchet.Tests
{
    class BytePrintHelper
    {
        public static string ByteArrayToByteArrayString(byte[] a)
        {
            // length = 11
            // new byte[] { 0x0a, 0x0b, 0x0c }
            Span<char> lookup = stackalloc char[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
            Span<char> pre = stackalloc char[] { 'n', 'e', 'w', ' ', 'b', 'y', 't', 'e', '[', ']', ' ' };
            Span<char> post = stackalloc char[] { ' ', '}' };
            Span<char> buff = stackalloc char[pre.Length + a.Length * 6 + post.Length];
            pre.CopyTo(buff);
            post.CopyTo(buff.Slice(buff.Length - post.Length, post.Length));

            for(int i=0;i<a.Length;i++)
            {
                int ix = pre.Length + i * 6;
                buff[ix] = i == 0 ? '{' : ',';
                buff[ix + 1] = ' ';
                buff[ix + 2] = '0';
                buff[ix + 3] = 'x';
                buff[ix + 4] = lookup[a[i] >> 4];
                buff[ix + 5] = lookup[a[i] & 0xf];
            }

            return new string(buff);
        }

        public static void PrintAsByteArray(string variableName, byte[] data)
        {
            var sb = new StringBuilder();
            sb.Append($"var {variableName} = {ByteArrayToByteArrayString(data)};");
            Debug.WriteLine(sb);
        }

        public static void PrintAsTheory(params object[] things)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("[InlineData(");

            for (int i=0;i<things.Length;i++)
            {
                var item = things[i];
                if (item == null)
                {
                    sb.Append("null");
                }
                if(item is byte[] bytearray)
                {
                    sb.Append(ByteArrayToByteArrayString(bytearray));
                }
                else
                {
                    sb.Append(item);
                }

                if (i != things.Length - 1)
                {
                    sb.Append(", ");
                }
            }

            sb.Append(")]");
            Debug.WriteLine(sb.ToString());
        }
    }
}
