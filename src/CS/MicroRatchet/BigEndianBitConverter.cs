using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    internal static class BigEndianBitConverter
    {
        public static byte[] GetBytes(int value) => new byte[]
        {
            (byte) ((value >> 24) & 0xFF),
            (byte) ((value >> 16) & 0xFF),
            (byte) ((value >> 8) & 0xFF),
            (byte) (value & 0xFF),
        };

        public static byte[] GetBytes(uint value) => new byte[]
        {
            (byte) ((value >> 24) & 0xFF),
            (byte) ((value >> 16) & 0xFF),
            (byte) ((value >> 8) & 0xFF),
            (byte) (value & 0xFF),
        };
        public static byte[] GetBytes(short value) => new byte[]
        {
            (byte) ((value >> 8) & 0xFF),
            (byte) (value & 0xFF),
        };

        public static byte[] GetBytes(ushort value) => new byte[]
        {
            (byte) ((value >> 8) & 0xFF),
            (byte) (value & 0xFF),
        };

        public static int ToInt32(byte[] value, int offset = 0) =>
                (value[offset + 0] << 24) |
                (value[offset + 1] << 16) |
                (value[offset + 2] << 8) |
                value[offset + 3];

        public static uint ToUInt32(byte[] value, int offset = 0) =>
            (uint)((value[offset + 0] << 24) |
                (value[offset + 1] << 16) |
                (value[offset + 2] << 8) |
                value[offset + 3]);

        public static int ToInt16(byte[] value, int offset = 0) =>
                (value[offset + 0] << 8) |
                value[offset + 1];

        public static uint ToUInt16(byte[] value, int offset = 0) =>
            (uint)((value[offset + 0] << 8) |
                value[offset + 1]);
    }
}
