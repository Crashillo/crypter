using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace Crypter
{
    public class MD5Encryption
    {
        private string keyPass = "ITKey";                                                        // IMPORTANT. This value is used to cipher data.

        public string doEncrypt(string cadena)
        {
            try
            {
                Byte[] llave, byteStr, bytResult = null;
                string sEncrypted = "";

                if (!String.IsNullOrEmpty(cadena))
                {
                    byteStr = UTF8Encoding.UTF8.GetBytes(cadena);                                   // Decryption string stored

                    // Encrypt using MD5 algorithm
                    MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
                    llave = md5.ComputeHash(UTF8Encoding.UTF8.GetBytes(keyPass));
                    md5.Clear();

                    // Encrypt using 3DES algorithm
                    TripleDESCryptoServiceProvider tripledes = new TripleDESCryptoServiceProvider();
                    tripledes.Key = llave;
                    tripledes.Mode = CipherMode.ECB;
                    tripledes.Padding = PaddingMode.PKCS7;
                    ICryptoTransform convertir = tripledes.CreateEncryptor();                            // String conversion
                    bytResult = convertir.TransformFinalBlock(byteStr, 0, byteStr.Length);        // Encrypted string stored
                    tripledes.Clear();

                    sEncrypted = Convert.ToBase64String(bytResult, 0, bytResult.Length);
                }

                return sEncrypted;
            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }
        }


        public string doDecrypt(string cadena)
        {
            try
            {
                Byte[] llave, byteStr, bytResult = null;
                string sDecrypted = null;
                string pattern64 = "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$";

                if ((!String.IsNullOrEmpty(cadena)) && (Regex.IsMatch(cadena, pattern64)))
                {
                    byteStr = Convert.FromBase64String(cadena);

                    // Encrypt using MD5 algorithm
                    MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
                    llave = md5.ComputeHash(UTF8Encoding.UTF8.GetBytes(keyPass));
                    md5.Clear();

                    // Encrypt using 3DES algorithm
                    TripleDESCryptoServiceProvider tripledes = new TripleDESCryptoServiceProvider();
                    tripledes.Key = llave;
                    tripledes.Mode = CipherMode.ECB;
                    tripledes.Padding = PaddingMode.PKCS7;
                    ICryptoTransform convertir = tripledes.CreateDecryptor();
                    bytResult = convertir.TransformFinalBlock(byteStr, 0, byteStr.Length);
                    tripledes.Clear();

                    sDecrypted = UTF8Encoding.UTF8.GetString(bytResult); 
                }

                return sDecrypted;
            }
            catch (Exception e)
            { 
                throw new Exception(e.Message);
            }                                  
        }
    }
}
