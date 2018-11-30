using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;

namespace CryptoMemoryStream.IO
{
	public class CryptoMemoryStream : MemoryStream
	{
		private CryptoStream writeStream;
		private CryptoStream readStream;
		private AesManaged aesManaged = new AesManaged();
		private readonly int writeableSize;

		public override int Capacity { 
			get => writeableSize; 
			set => base.Capacity = (value / 16 + 1) * 16; 
		}

		public CryptoMemoryStream(int size, byte[] key) : base((size / 16 + 1) * 16)
		{
			aesManaged.Key = key;
			aesManaged.IV = key;
			writeableSize = size;

			writeStream = new CryptoStream(this, aesManaged.CreateEncryptor(), CryptoStreamMode.Write);
			readStream = new CryptoStream(this, aesManaged.CreateDecryptor(), CryptoStreamMode.Read);
		}

		public new void Write(byte[] buffer, int offset, int count)
		{
			writeStream.Write(buffer, offset, count);
		}

		public new int Read(byte[] buffer, int offset, int count)
		{
			return readStream.Read(buffer, offset, count);
		}	
	}
}
