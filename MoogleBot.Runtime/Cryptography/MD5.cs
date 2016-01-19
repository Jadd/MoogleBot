using System;

namespace MoogleBot.Runtime.Cryptography {
    public class MD5 {

        #region Constants
        private static readonly byte[][] _matrix = {
            new byte[] { 07, 12, 17, 22 },
            new byte[] { 05, 09, 14, 20 },
            new byte[] { 04, 11, 16, 23 },
            new byte[] { 06, 10, 15, 21 }
        };

        private static readonly uint[] _digest = {
            0x67452301, 0xEFCDAB89,
            0x98BADCFE, 0x10325476
        };
        #endregion
        
        #region Arithmetic Methods
        private static uint F(uint x, uint y, uint z) {
            return (x & y) | (~x & z);
        }

        private static uint G(uint x, uint y, uint z) {
            return (x & z) | (y & ~z);
        }

        private static uint H(uint x, uint y, uint z) {
            return x ^ y ^ z;
        }

        private static uint I(uint x, uint y, uint z) {
            return y ^ (x | ~z);
        }

        private static uint ROTATE_LEFT(uint x, byte n) {
            return (x << n) | (x >> (32 - n));
        }

        private static void FF(ref uint a, uint b, uint c, uint d, uint x, byte s, uint ac) {
            a += F(b, c, d) + x + ac;
            a = ROTATE_LEFT(a, s);
            a += b;
        }

        private static void GG(ref uint a, uint b, uint c, uint d, uint x, byte s, uint ac) {
            a += G(b, c, d) + x + ac;
            a = ROTATE_LEFT(a, s);
            a += b;
        }

        private static void HH(ref uint a, uint b, uint c, uint d, uint x, byte s, uint ac) {
            a += H(b, c, d) + x + ac;
            a = ROTATE_LEFT(a, s);
            a += b;
        }

        private static void II(ref uint a, uint b, uint c, uint d, uint x, byte s, uint ac) {
            a += I(b, c, d) + x + ac;
            a = ROTATE_LEFT(a, s);
            a += b;
        }
        #endregion
        
        public static byte[] Transform(byte[] buffer) {
            uint a = _digest[0], b = _digest[1],
                 c = _digest[2], d = _digest[3];

            // Store length information.
            var origLength = buffer.Length;
            var origBits = (ulong) origLength * 8;

            // Add padding to 64 bytes.
            var padLength = 64 - (origLength % 64);
            
            // Create the new buffer with correct size.
            var block = new byte[origLength + padLength];
            Buffer.BlockCopy(buffer, 0, block, 0, origLength);
            
            // Set padding indicator bit.
            block[origLength] = 0x80;
            Buffer.BlockCopy(BitConverter.GetBytes(origBits), 0, block, block.Length - 8, 8);

            // Initialize the buffer for the resulting hash.
            var data = new uint[16];
            for (var i = 0; i < 16; i++)
                data[i] = BitConverter.ToUInt32(block, i * 4);
            
            // Round 1.
            FF(ref a, b, c, d, data[00], _matrix[0][0], 0xD76AA478); /* 01 */
            FF(ref d, a, b, c, data[01], _matrix[0][1], 0xE8C7B756); /* 02 */
            FF(ref c, d, a, b, data[02], _matrix[0][2], 0x242070DB); /* 03 */
            FF(ref b, c, d, a, data[03], _matrix[0][3], 0xC1BDCEEE); /* 04 */
            FF(ref a, b, c, d, data[04], _matrix[0][0], 0xF57C0FAF); /* 05 */
            FF(ref d, a, b, c, data[05], _matrix[0][1], 0x4787C62A); /* 06 */
            FF(ref c, d, a, b, data[06], _matrix[0][2], 0xA8304613); /* 07 */
            FF(ref b, c, d, a, data[07], _matrix[0][3], 0xFD469501); /* 08 */
            FF(ref a, b, c, d, data[08], _matrix[0][0], 0x698098D8); /* 09 */
            FF(ref d, a, b, c, data[09], _matrix[0][1], 0x8B44F7AF); /* 10 */
            FF(ref c, d, a, b, data[10], _matrix[0][2], 0xFFFF5BB1); /* 11 */
            FF(ref b, c, d, a, data[11], _matrix[0][3], 0x895CD7BE); /* 12 */
            FF(ref a, b, c, d, data[12], _matrix[0][0], 0x6B901122); /* 13 */
            FF(ref d, a, b, c, data[13], _matrix[0][1], 0xFD987193); /* 14 */
            FF(ref c, d, a, b, data[14], _matrix[0][2], 0xA679438E); /* 15 */
            FF(ref b, c, d, a, data[15], _matrix[0][3], 0x49B40821); /* 16 */

            // Round 2.
            GG(ref a, b, c, d, data[01], _matrix[1][0], 0xF61E2562); /* 17 */
            GG(ref d, a, b, c, data[06], _matrix[1][1], 0xC040B340); /* 18 */
            GG(ref c, d, a, b, data[11], _matrix[1][2], 0x265E5A51); /* 19 */
            GG(ref b, c, d, a, data[00], _matrix[1][3], 0xE9B6C7AA); /* 20 */
            GG(ref a, b, c, d, data[05], _matrix[1][0], 0xD62F105D); /* 21 */
            GG(ref d, a, b, c, data[10], _matrix[1][1], 0x02441453); /* 22 */
            GG(ref c, d, a, b, data[15], _matrix[1][2], 0xD8A1E681); /* 23 */
            GG(ref b, c, d, a, data[04], _matrix[1][3], 0xE7D3FBC8); /* 24 */
            GG(ref a, b, c, d, data[09], _matrix[1][0], 0x21E1CDE6); /* 25 */
            GG(ref d, a, b, c, data[14], _matrix[1][1], 0xC33707D6); /* 26 */
            GG(ref c, d, a, b, data[03], _matrix[1][2], 0xF4D50D87); /* 27 */
            GG(ref b, c, d, a, data[08], _matrix[1][3], 0x455A14ED); /* 28 */
            GG(ref a, b, c, d, data[13], _matrix[1][0], 0xA9E3E905); /* 29 */
            GG(ref d, a, b, c, data[02], _matrix[1][1], 0xFCEFA3F8); /* 30 */
            GG(ref c, d, a, b, data[07], _matrix[1][2], 0x676F02D9); /* 31 */
            GG(ref b, c, d, a, data[12], _matrix[1][3], 0x8D2A4C8A); /* 32 */

            // Round 3.
            HH(ref a, b, c, d, data[05], _matrix[2][0], 0xFFFA3942); /* 33 */
            HH(ref d, a, b, c, data[08], _matrix[2][1], 0x8771F681); /* 34 */
            HH(ref c, d, a, b, data[11], _matrix[2][2], 0x6D9D6122); /* 35 */
            HH(ref b, c, d, a, data[14], _matrix[2][3], 0xFDE5380C); /* 36 */
            HH(ref a, b, c, d, data[01], _matrix[2][0], 0xA4BEEA44); /* 37 */
            HH(ref d, a, b, c, data[04], _matrix[2][1], 0x4BDECFA9); /* 38 */
            HH(ref c, d, a, b, data[07], _matrix[2][2], 0xF6BB4B60); /* 39 */
            HH(ref b, c, d, a, data[10], _matrix[2][3], 0xBEBFBC70); /* 40 */
            HH(ref a, b, c, d, data[13], _matrix[2][0], 0x289B7EC6); /* 41 */
            HH(ref d, a, b, c, data[00], _matrix[2][1], 0xEAA127FA); /* 42 */
            HH(ref c, d, a, b, data[03], _matrix[2][2], 0xD4EF3085); /* 43 */
            HH(ref b, c, d, a, data[06], _matrix[2][3], 0x04881D05); /* 44 */
            HH(ref a, b, c, d, data[09], _matrix[2][0], 0xD9D4D039); /* 45 */
            HH(ref d, a, b, c, data[12], _matrix[2][1], 0xE6DB99E5); /* 46 */
            HH(ref c, d, a, b, data[15], _matrix[2][2], 0x1FA27CF8); /* 47 */
            HH(ref b, c, d, a, data[02], _matrix[2][3], 0xC4AC5665); /* 48 */

            // Round 4.
            II(ref a, b, c, d, data[00], _matrix[3][0], 0xF4292244); /* 49 */
            II(ref d, a, b, c, data[07], _matrix[3][1], 0x432AFF97); /* 50 */
            II(ref c, d, a, b, data[14], _matrix[3][2], 0xAB9423A7); /* 51 */
            II(ref b, c, d, a, data[05], _matrix[3][3], 0xFC93A039); /* 52 */
            II(ref a, b, c, d, data[12], _matrix[3][0], 0x655B59C3); /* 53 */
            II(ref d, a, b, c, data[03], _matrix[3][1], 0x8F0CCC92); /* 54 */
            II(ref c, d, a, b, data[10], _matrix[3][2], 0xFFEFF47D); /* 55 */
            II(ref b, c, d, a, data[01], _matrix[3][3], 0x85845DD1); /* 56 */
            II(ref a, b, c, d, data[08], _matrix[3][0], 0x6FA87E4F); /* 57 */
            II(ref d, a, b, c, data[15], _matrix[3][1], 0xFE2CE6E0); /* 58 */
            II(ref c, d, a, b, data[06], _matrix[3][2], 0xA3014314); /* 59 */
            II(ref b, c, d, a, data[13], _matrix[3][3], 0x4E0811A1); /* 60 */
            II(ref a, b, c, d, data[04], _matrix[3][0], 0xF7537E82); /* 61 */
            II(ref d, a, b, c, data[11], _matrix[3][1], 0xBD3AF235); /* 62 */
            II(ref c, d, a, b, data[02], _matrix[3][2], 0x2AD7D2BB); /* 63 */
            II(ref b, c, d, a, data[09], _matrix[3][3], 0xEB86D391); /* 64 */

            var result = new byte[16];
            Buffer.BlockCopy(BitConverter.GetBytes(_digest[0] + a), 0, result, 00, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(_digest[1] + b), 0, result, 04, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(_digest[2] + c), 0, result, 08, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(_digest[3] + d), 0, result, 12, 4);

            return result;
        }

    }
}
