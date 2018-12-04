using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;

namespace CryptoMemoryStream.IO
{
	/// <summary>
	/// 백업 저장소가 메모리이면서 읽기 또는 쓰기 과정에서 복호화 또는 암호화가 가능한 스트림을 만듭니다.
	/// </summary>
	public class CryptoMemoryStream : MemoryStream
	{
		private ICryptoTransform cryptor;

		private AesCryptoServiceProvider aesManaged = new AesCryptoServiceProvider
		{
			Padding = PaddingMode.None,
			Mode = CipherMode.ECB
		};

		/// <summary>
		/// 지정된 바이트 배열을 기반으로 하는 CryptoMemoryStream 클래스의 크기 조정이 불가능한 새 인스턴스를 초기화합니다.
		/// </summary>
		/// <param name="buffer">현재 스트림을 만들 부호 없는 바이트의 배열입니다.</param>
		/// /// <param name="key">암호화 및 복호화에 사용되는 키 값입니다.</param>
		public CryptoMemoryStream(byte[] buffer, byte[] key) : base(buffer)
		{
			InitializeCryptor(key);
		}

		/// <summary>
		/// 지정된 대로 초기화된 확장명 가능한 용량을 사용하고 지정된 키 값으로 암호화 되는 CryptoMemoryStream 클래스의 새 인스턴스를 초기화합니다.
		/// </summary>
		/// <param name="size">내부 배열의 초기 크기(바이트)입니다.</param>
		/// <param name="key">암호화 및 복호화에 사용되는 키 값입니다.</param>
		public CryptoMemoryStream(int size, byte[] key) : base(size)
		{
			InitializeCryptor(key);
		}

		/// <summary>
		/// 0으로 초기화된 확장명 가능한 용량을 사용하여 CryptoMemoryStream 클래스의 새 인스턴스를 초기화합니다.
		/// </summary>
		/// <param name="key">암호화 및 복호화에 사용되는 키 값입니다.</param>
		public CryptoMemoryStream(byte[] key) : base()
		{
			InitializeCryptor(key);
		}

		/// <summary>
		/// 초기화된 MemoryStream 클래스의 인스턴스를 이용하여 CryptoMemoryStream을 생성합니다.
		/// </summary>
		/// <param name="baseStream">GetBuffer() 메소드를 호출하여 버퍼를 획득할 MemoryStream 클래스의 인스턴스입니다.</param>
		/// <param name="key">암호화 및 복호화에 사용되는 키 값입니다.</param>
		/// <returns>전달된 MemoryStream 인스턴스의 GetBuffer() 메소드를 호출하여 얻은 버퍼와 키 값으로 초기화된 CryptoMemoryStream 클래스의 인스턴스입니다.</returns>
		public static CryptoMemoryStream Create(MemoryStream baseStream, byte[] key)
		{
			return new CryptoMemoryStream(baseStream.GetBuffer(), key);
		}

		private void InitializeCryptor(byte[] key)
		{
			cryptor = aesManaged.CreateEncryptor();
			aesManaged.KeySize = key.Length * 8;
			aesManaged.Key = key;
			aesManaged.IV = key;
		}

		/// <summary>
		/// 버퍼에서 읽은 데이터를 사용하여 현재 스트림에 바이트 블록을 암호화 후 씁니다.
		/// </summary>
		/// <param name="buffer">암호화할 데이터를 쓸 버퍼입니다.</param>
		/// <param name="offset">현재 스트림으로 바이트를 복사하기 시작할 buffer의 바이트 오프셋(0부터 시작)입니다.</param>
		/// <param name="count">쓸 최대 바이트 수입니다.</param>
		public override void Write(byte[] buffer, int offset, int count)
		{
			byte[] encryptBytes = (byte[])buffer.Clone();

			CTRCryptor(encryptBytes, offset, count);
			base.Write(encryptBytes, offset, count);
		}

		/// <summary>
		/// 현재 스트림에서 바이트 블록을 읽어서 버퍼에 씁니다.
		/// </summary>
		/// <param name="buffer">이 메서드는 지정된 바이트 배열의 값이 offset과 (offset + count - 1) 사이에서 현재 원본으로부터 읽어온 바이트로 교체된 상태로 반환됩니다.</param>
		/// <param name="offset">현재 스트림으로 바이트를 복사하기 시작할 buffer의 바이트 오프셋(0부터 시작)입니다.</param>
		/// <param name="count">쓸 최대 바이트 수입니다.</param>
		/// <returns>버퍼로 쓴 총 바이트 수입니다. 해당 바이트 수를 현재 사용할 수 없는 경우 이 수는 요청된 바이트 수보다 작을 수 있으며 바이트를 읽기 전에 스트림의 끝에 도달한 경우에는 0이 될 수도 있습니다.</returns>
		public override int Read(byte[] buffer, int offset, int count)
		{
			Position = Math.Max(Position - count, 0);
			int readedSize = base.Read(buffer, offset, count);
			SetLength(Position);

			return readedSize;
		}

		/// <summary>
		/// 버퍼에서 읽은 데이터를 사용하여 현재 스트림에 바이트 블록을 하여 씁니다.
		/// </summary>
		/// <param name="buffer">데이터를 쓸 버퍼입니다.</param>
		/// <param name="offset">현재 스트림으로 바이트를 복사하기 시작할 buffer의 바이트 오프셋(0부터 시작)입니다.</param>
		/// <param name="count">쓸 최대 바이트 수입니다.</param>
		public void Encrypt(byte[] buffer, int offset, int count)
		{
			base.Write(buffer, offset, count);
		}

		/// <summary>
		/// 현재 스트림에서 바이트 블록을 읽어서 복호화 후 버퍼에 씁니다.
		/// </summary>
		/// <param name="buffer">이 메서드는 지정된 바이트 배열의 값이 offset과 (offset + count - 1) 사이에서 현재 원본으로부터 읽어온 바이트로 교체된 상태로 반환됩니다.</param>
		/// <param name="offset">현재 스트림으로 바이트를 복사하기 시작할 buffer의 바이트 오프셋(0부터 시작)입니다.</param>
		/// <param name="count">쓸 최대 바이트 수입니다.</param>
		/// <returns>버퍼로 쓴 총 바이트 수입니다. 해당 바이트 수를 현재 사용할 수 없는 경우 이 수는 요청된 바이트 수보다 작을 수 있으며 바이트를 읽기 전에 스트림의 끝에 도달한 경우에는 0이 될 수도 있습니다.</returns>
		public int Decrypt(byte[] buffer, int offset, int count)
		{
			int readedSize = Read(buffer, offset, count);
			CTRCryptor(buffer, offset, readedSize);

			return readedSize;
		}

		/// <summary>
		/// 현재 스트림을 닫고 현재 스트림과 관련된 소켓과 파일 핸들 등의 리소스를 모두 해제합니다. 이 메서드를 호출하는 대신 스트림이 올바르게 삭제되었는지 확인합니다.
		/// </summary>
		public override void Close()
		{
			cryptor.Dispose();
			aesManaged.Dispose();

			base.Close();
		}

		private void CTRCryptor(byte[] buffer, int offset, int count)
		{
			Queue<byte> xorMask = new Queue<byte>();
			int blockSize = aesManaged.BlockSize / 8;
			byte[] counter = (byte[]) aesManaged.Key.Clone();
			for (int i = 0; i < count; i++)
			{
				if (xorMask.Count == 0)
				{
					var counterModeBlock = new byte[blockSize];

					cryptor.TransformBlock(counter, 0, counter.Length, counterModeBlock, 0);

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
