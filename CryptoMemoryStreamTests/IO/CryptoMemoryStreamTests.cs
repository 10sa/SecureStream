using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

using CryptoStream;

namespace CryptoStream.IO.Tests
{
	[TestClass()]
	public class CryptoMemoryStreamTests
	{
		public byte[] plainKey = new byte[32];
		public byte[] data;

		public CryptoMemoryStreamTests()
		{
			data = Encoding.UTF8.GetBytes("ASDSADFSADFSAFSDAFSAFASDFASDSADFASSAFSADFSADGDSFSADFSDAFASDFSDAFASFSDAFASF");
		}

		[TestMethod()]
		public void WriteTest()
		{
			CryptoMemoryStream memoryStream = new CryptoMemoryStream(1024, plainKey);

			memoryStream.Encrypt(data, 0, data.Length);
		}

		[TestMethod()]
		public void ReadTest()
		{
			CryptoMemoryStream memoryStream = new CryptoMemoryStream(1024, plainKey);
			byte[] buffer = new byte[data.Length];

			memoryStream.Encrypt(data, 0, data.Length);
			Console.WriteLine(memoryStream.Decrypt(buffer, 0, buffer.Length));
			Console.WriteLine(string.Join(" ", buffer));

			Assert.IsTrue(data.SequenceEqual(buffer));
		}

		[TestMethod()]
		public void DuplexRWTest()
		{
			CryptoMemoryStream memoryStream = new CryptoMemoryStream(1024, plainKey);
			byte[] buffer = new byte[data.Length];

			for (int i = 0; i < 2; i++)
			{
				memoryStream.Encrypt(data, 0, data.Length);
				Console.WriteLine(memoryStream.Decrypt(buffer, 0, buffer.Length));
				Console.WriteLine(string.Join(" ", buffer));

				Assert.IsTrue(data.SequenceEqual(buffer));
			}
		}

		[TestMethod()]
		public void AESIVSizeTest()
		{
			AesCryptoServiceProvider aesManaged = new AesCryptoServiceProvider
			{
				Padding = PaddingMode.None,
				Mode = CipherMode.ECB
			};

			aesManaged.KeySize = 256;
			aesManaged.GenerateIV();
			aesManaged.GenerateKey();

			Console.WriteLine("IV Length : " + aesManaged.IV.Length);
			Console.WriteLine("Key Length : " + aesManaged.Key.Length);
		}
	}
}