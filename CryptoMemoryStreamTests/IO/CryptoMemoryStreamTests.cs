using Microsoft.VisualStudio.TestTools.UnitTesting;
using CryptoMemoryStream.IO;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoMemoryStream.IO.Tests
{
	[TestClass()]
	public class CryptoMemoryStreamTests
	{
		public byte[] plainKey = new byte[16];
		public byte[] data = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF };

		[TestMethod()]
		public void WriteTest()
		{
			CryptoMemoryStream memoryStream = new CryptoMemoryStream(1024, plainKey);

			memoryStream.Write(data, 0, data.Length);
		}

		[TestMethod()]
		public void ReadTest()
		{
			CryptoMemoryStream memoryStream = new CryptoMemoryStream(1024, plainKey);
			byte[] buffer = new byte[16];

			memoryStream.Write(data, 0, data.Length);
			Console.WriteLine(memoryStream.Read(buffer, 0, buffer.Length));
			Console.WriteLine(string.Join(" ", buffer));
		}

		[TestMethod()]
		public void DuplexRWTest()
		{
			CryptoMemoryStream memoryStream = new CryptoMemoryStream(1024, plainKey);
			byte[] buffer = new byte[16];

			for (int i = 0; i < 2; i++)
			{
				memoryStream.Position = 0;
				memoryStream.Write(data, 0, data.Length);
				Console.WriteLine(memoryStream.Read(buffer, 0, buffer.Length));
				Console.WriteLine(string.Join(" ", buffer));
			}
		}
	}
}