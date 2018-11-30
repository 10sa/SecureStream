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
		private ICryptoTransform crypter;

		private AesCryptoServiceProvider aesManaged = new AesCryptoServiceProvider
		{
			Padding = PaddingMode.None,
			Mode = CipherMode.ECB
		};

		public CryptoMemoryStream(int size, byte[] key)  : base(size)
		{
			aesManaged.KeySize = key.Length * 8;
			aesManaged.Key = key;
			aesManaged.IV = key;

			crypter = aesManaged.CreateEncryptor();
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			CTRAlgorithm(buffer, offset, count);
			base.Write(buffer, offset, count);
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			Position = Math.Max(Position - count, 0);
			int readedSize = base.Read(buffer, offset, count);

			return readedSize;
		}

		public void Encrypt(byte[] buffer, int offset, int count)
		{
			base.Write(buffer, offset, count);
		}

		public int Decrypt(byte[] buffer, int offset, int count)
		{
			Position = Math.Max(Position - count, 0);
			int readedSize = base.Read(buffer, offset, count);
			CTRAlgorithm(buffer, offset, readedSize);

			return readedSize;
		}

		private void CTRAlgorithm(byte[] buffer, int offset, int count)
		{
			Queue<byte> xorMask = new Queue<byte>();
			int blockSize = aesManaged.BlockSize / 8;
			byte[] counter = (byte[]) aesManaged.Key.Clone();
			for (int i = 0; i < count; i++)
			{
				if (xorMask.Count == 0)
				{
					var counterModeBlock = new byte[blockSize];

					crypter.TransformBlock(counter, 0, counter.Length, counterModeBlock, 0);

					for (var _i = counter.Length - 1; _i >= 0; _i--)
					{
						if (++counter[_i] != 0)
							break;
					}

					foreach (var j in counterModeBlock)
						xorMask.Enqueue(j);
				}

				buffer[i] = (byte)(buffer[i] ^ xorMask.Dequeue());
			}
		}
	}
}
