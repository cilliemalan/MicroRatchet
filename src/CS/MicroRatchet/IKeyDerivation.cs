﻿using System;

namespace MicroRatchet
{
    internal interface IKeyDerivation
    {
        byte[] GenerateBytes(byte[] key, byte[] info, int howManyBytes);
    }
}