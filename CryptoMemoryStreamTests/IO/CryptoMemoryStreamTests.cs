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
		public byte[] data = new byte[16];

		[TestMethod()]
		public void WriteTest()
		{
			CryptoMemoryStream memoryStream = new CryptoMemoryStream(1024, plainKey);

			memoryStream.Write(data, 0, data.Length);
		}
	}
}