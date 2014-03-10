using System;
using NUnit.Framework;
using OpenSSL.Crypto;
using System.Text;
using System.Reflection;
using OpenSSL.Core;
using System.Collections.Generic;

namespace UnitTests
{
	[TestFixture]
	public class TestCipher
	{
		[Test]
		public void TestEncryptDecrypt()
		{
            string inputMsg = "The quick brown fox jumped over the lazy dog. The quick brown fox jumped over the lazy dog. The quick brown fox jumped over the lazy dog.";
			byte[] input = Encoding.ASCII.GetBytes(inputMsg);
			byte[] iv = Encoding.ASCII.GetBytes("12345678");
			byte[] key = Encoding.ASCII.GetBytes("This is the key");

			foreach (var cipher in Ciphers(false)) {
				Console.Write("Using cipher {0}: ", cipher.LongName);
				using (var cc = new CipherContext(cipher)) {
					Console.Write(" KeyLength: {0}, IVLength: {1}, BlockSize: {2}, Stream: {3} ",
					              cipher.KeyLength, cipher.IVLength, cipher.BlockSize, cc.IsStream);

                    EncryptCipherContext ec = new EncryptCipherContext(cipher, key, iv, -1);
                    DecryptCipherContext dc = new DecryptCipherContext(cipher, key, iv, -1);

                    for (int i = 0; i < 3; i++)
                    {
                        var pt = ec.Encrypt(input, input.Length);
                        if (cipher != Cipher.Null)
                            Assert.AreNotEqual(input, pt);

                        var ct = dc.Decrypt(pt, pt.Length);
                        var msg = Encoding.ASCII.GetString(ct);
                        Console.WriteLine("\"{0}\"", msg);
                        Assert.AreEqual(inputMsg, msg);
                    }
				    dc.Dispose();
                    ec.Dispose();
				}
			}
		}

		[Test]
		public void TestEncryptDecryptWithSalt()
		{
			string inputMsg = "This is a message";
			byte[] input = Encoding.ASCII.GetBytes(inputMsg);
			byte[] salt = Encoding.ASCII.GetBytes("salt");
			byte[] secret = Encoding.ASCII.GetBytes("Password!");
			
			foreach (var cipher in Ciphers(true)) {
				Console.Write("Using cipher {0}: ", cipher.LongName);
				using (var cc = new CipherContext(cipher)) {
					Console.Write(" KeyLength: {0}, IVLength: {1}, BlockSize: {2}, Stream: {3} ",
					              cipher.KeyLength, cipher.IVLength, cipher.BlockSize, cc.IsStream);
					byte[] iv;
					byte[] key = cc.BytesToKey(MessageDigest.SHA1, salt, secret, 1, out iv);
					
					var pt = cc.Encrypt(input, key, iv);
					Assert.AreNotEqual(input, pt);
					
					var ct = cc.Decrypt(pt, key, iv);
					var msg = Encoding.ASCII.GetString(ct);
					Console.WriteLine("\"{0}\"", msg);
					Assert.AreEqual(inputMsg, msg);
				}
			}
		}
		
		private static IEnumerable<Cipher> Ciphers(bool skipNull) 
		{
			foreach (var pi in typeof(Cipher).GetFields(BindingFlags.Public | BindingFlags.Static)) {
				var cipher = (Cipher)pi.GetValue(null);
				if (cipher == Cipher.Null && skipNull)
					continue;
				yield return cipher;
			}
			
		}
		
		[Test]
		public void TestSealOpen()
		{
			string inputMsg = "This is a message";
			byte[] input = Encoding.ASCII.GetBytes(inputMsg);
			const int numKeys = 10;
			var rsas = new RSA[numKeys];
			var pkeys = new CryptoKey[numKeys];
			for (int i = 0; i < numKeys; i++) {
				rsas[i] = new RSA();
				rsas[i].GenerateKeys(1024, BigNumber.One, null, null);
				pkeys[i] = new CryptoKey(rsas[i]);
			}
			
			try {
				foreach (var cipher in Ciphers(true)) {
					using (var cc = new CipherContext(cipher)) {
						var env = cc.Seal(pkeys, input);
						Assert.AreNotEqual(input, env.Data);
						
						for (int i = 0; i < numKeys; i++) {
							var result = cc.Open(env.Data, env.Keys[i], env.IV, pkeys[i]);
							Assert.AreEqual(input, result);
						}
					}
				}
			}
			finally {
				for (int i = 0; i < numKeys; i++) {
					pkeys[i].Dispose();
					rsas[i].Dispose();
				}
			}
		}
	}
}


			