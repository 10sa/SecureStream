using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;
using System.Threading;

namespace SecureStream
{
	/// <summary>
	/// 백업 저장소가 메모리이면서 읽기 또는 쓰기 과정에서 복호화 또는 암호화가 가능한 스트림을 만듭니다.
	/// </summary>
	public class CryptoMemoryStream : MemoryStream
	{
		/// <summary>
		/// 암호화 작업에 사용되는 암호화 키입니다.
		/// </summary>
		public byte[] Key { get { return aesManaged.Key; } set { aesManaged.Key = value; } }

		/// <summary>
		/// 암호화 작업에 사용되는 초기화 벡터입니다.
		/// </summary>
		public byte[] IV { get { return aesManaged.IV; } set { aesManaged.IV = value; } }

		private ICryptoTransform cryptor;

		private readonly AesCryptoServiceProvider aesManaged = new AesCryptoServiceProvider
		{
			Padding = PaddingMode.None,
			Mode = CipherMode.ECB
		};

		/// <summary>
		/// 지정된 버퍼를 기반으로 하는 크기 조정이 불가능한 CryptoMemoryStream 클래스의 새 인스턴스를 초기화합니다.
		/// </summary>
		/// <param name="buffer">현재 스트림의 버퍼가 될 버퍼입니다.</param>
		/// <param name="key">암호화 및 복호화에 사용되는 키입니다.</param>
		/// <param name="initializeVector">암호화 및 복호화에 사용될 초기화 벡터입니다.</param>
		public CryptoMemoryStream(byte[] buffer, byte[] key, byte[] initializeVector) : base(buffer)
		{
			InitializeCryptor(key, initializeVector);
		}

		/// <summary>
		/// 지정된 용량을 가진 확장 가능한 CryptoMemoryStream 클래스의 새 인스턴스를 초기화합니다.
		/// </summary>
		/// <param name="size">내부 버퍼의 초기 크기(바이트)입니다.</param>
		/// <param name="key">암호화 및 복호화에 사용되는 키입니다.</param>
		/// <param name="initializeVector">암호화 및 복호화에 사용될 초기화 벡터입니다.</param>
		public CryptoMemoryStream(int size, byte[] key, byte[] initializeVector) : base(size)
		{
			InitializeCryptor(key, initializeVector);
		}

		/// <summary>
		/// 0의 용량을 가진 확장 가능한 CryptoMemoryStream 클래스의 새 인스턴스를 초기화합니다.
		/// </summary>
		/// <param name="key">암호화 및 복호화에 사용되는 키입니다.</param>
		/// <param name="initializeVector">암호화 및 복호화에 사용될 초기화 벡터입니다.</param>
		public CryptoMemoryStream(byte[] key, byte[] initializeVector) : base()
		{
			InitializeCryptor(key, initializeVector);
		}

		/// <summary>
		/// 0의 용량을 가진 확장 가능한 CryptoMemoryStream 클래스의 새 인스턴스를 초기화합니다.
		/// </summary>
		/// <param name="size">내부 버퍼의 초기 크기(바이트)입니다.</param>
		/// <param name="key">암호화 및 복호화에 사용되는 키입니다.</param>
		public CryptoMemoryStream(int size, byte[] key) : base(size)
		{
			InitializeCryptor(key);
		}

		/// <summary>
		/// 0의 용량을 가진 확장 가능한 CryptoMemoryStream 클래스의 새 인스턴스를 초기화합니다.
		/// </summary>
		/// <param name="key">암호화 및 복호화에 사용되는 키입니다.</param>
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

		private void InitializeCryptor(byte[] key, byte[] initializeVector)
		{
			aesManaged.Key = key;
			aesManaged.IV = initializeVector;
			cryptor = aesManaged.CreateEncryptor();
		}

		private void InitializeCryptor(byte[] key)
		{
			aesManaged.Key = key;
			cryptor = aesManaged.CreateEncryptor();
		}

		/// <summary>
		/// 버퍼에서 읽은 데이터를 사용하여 현재 스트림에 바이트 블록을 암호화 후 씁니다.
		/// </summary>
		/// <param name="buffer">암호화할 데이터를 쓸 버퍼입니다.</param>
		/// <param name="offset">현재 스트림으로 바이트를 복사하기 시작할 buffer의 바이트 오프셋(0부터 시작)입니다.</param>
		/// <param name="count">쓸 최대 바이트 수입니다.</param>
		public override void Write(byte[] buffer, int offset, int count)
		{
			base.Write(buffer, offset, count);
		}

		/// <summary>
		/// 현재 스트림에서 바이트 블록을 읽어서 버퍼에 쓰고 읽어들인 부분을 0으로 채웁니다.
		/// </summary>
		/// <param name="buffer">이 메서드는 지정된 바이트 배열의 값이 offset과 (offset + count - 1) 사이에서 현재 원본으로부터 읽어온 바이트로 교체된 상태로 반환됩니다.</param>
		/// <param name="offset">현재 스트림으로 바이트를 복사하기 시작할 buffer의 바이트 오프셋(0부터 시작)입니다.</param>
		/// <param name="count">쓸 최대 바이트 수입니다.</param>
		/// <returns>버퍼로 쓴 총 바이트 수입니다. 해당 바이트 수를 현재 사용할 수 없는 경우 이 수는 요청된 바이트 수보다 작을 수 있으며 바이트를 읽기 전에 스트림의 끝에 도달한 경우에는 0이 될 수도 있습니다.</returns>
		public override int Read(byte[] buffer, int offset, int count)
		{
			return Read(buffer, offset, count, true);
		}

		/// <summary>
		/// 현재 스트림에서 바이트 블록을 읽어서 버퍼에 씁니다.
		/// </summary>
		/// <param name="buffer">이 메서드는 지정된 바이트 배열의 값이 offset과 (offset + count - 1) 사이에서 현재 원본으로부터 읽어온 바이트로 교체된 상태로 반환됩니다.</param>
		/// <param name="offset">현재 스트림으로 바이트를 복사하기 시작할 buffer의 바이트 오프셋(0부터 시작)입니다.</param>
		/// <param name="count">쓸 최대 바이트 수입니다.</param>
		/// <param name="erase">읽어들인 스트림 위치의 데이터를 0으로 채울지에 대한 여부입니다.</param>
		/// <returns>버퍼로 쓴 총 바이트 수입니다. 해당 바이트 수를 현재 사용할 수 없는 경우 이 수는 요청된 바이트 수보다 작을 수 있으며 바이트를 읽기 전에 스트림의 끝에 도달한 경우에는 0이 될 수도 있습니다.</returns>
		public int Read(byte[] buffer, int offset, int count, bool erase)
		{
			int streamPosition = (int)Math.Max(Position - count, 0);

			Position = streamPosition;
			int readedSize = base.Read(buffer, offset, count);

			Position = streamPosition;
			SetLength(Position);

			if (erase)
			{
				for (int i = 0; i < readedSize; i++)
					WriteByte(0);
			}

			Position = streamPosition;
			SetLength(Position);
			return readedSize;
		}

		/// <summary>
		/// 버퍼에서 읽은 데이터를 사용하여 현재 스트림에 바이트 블록을 암호화 하여 씁니다.
		/// </summary>
		/// <param name="buffer">데이터를 쓸 버퍼입니다.</param>
		/// <param name="offset">현재 스트림으로 바이트를 복사하기 시작할 buffer의 바이트 오프셋(0부터 시작)입니다.</param>
		/// <param name="count">쓸 최대 바이트 수입니다.</param>
		public void Encrypt(byte[] buffer, int offset, int count)
		{
			byte[] encryptBytes = (byte[])buffer.Clone();

			CTRCryptor(encryptBytes, count);
			base.Write(encryptBytes, offset, count);
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
			CTRCryptor(buffer, readedSize);

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

		private void CTRCryptor(byte[] buffer, int count)
		{
			Queue<byte> xorMask = new Queue<byte>();
			int blockSize = aesManaged.Key.Length;
			byte[] counter = (byte[]) aesManaged.IV.Clone();
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

		/// <summary>
		/// CryptoMemoryStream 에 사용되는 관리되지 않는 리소스를 제거하고, 필요에 따라 관리되는 리소스를 해제합니다.
		/// </summary>
		/// <param name="disposing"></param>
		protected override void Dispose(bool disposing)
		{
			base.Dispose(disposing);
			aesManaged.Dispose();
			cryptor.Dispose();
		}

		/// <summary>
		/// 현재 위치에서 현재 스트림에 바이트를 암호화 하여 씁니다.
		/// </summary>
		/// <param name="value"></param>
		public override void WriteByte(byte value)
		{
			Write(new byte[] { value }, 0, 1);
		}

		/// <summary>
		/// MemoryStream.BeginRead 메소드를 재정의하여 아무것도 하지 않도록 합니다.
		/// </summary>
		public override IAsyncResult BeginRead(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
		{
			throw new InvalidOperationException("사용이 불가능한 메소드입니다.");
		}

		/// <summary>
		/// MemoryStream.EndRead 메소드를 재정의하여 아무것도 하지 않도록 합니다.
		/// </summary>
		public override int EndRead(IAsyncResult asyncResult)
		{
			throw new InvalidOperationException("사용이 불가능한 메소드입니다.");
		}

		/// <summary>
		/// MemoryStream.BeginWrite 메소드를 재정의하여 아무것도 하지 않도록 합니다.
		/// </summary>
		public override IAsyncResult BeginWrite(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
		{
			throw new InvalidOperationException("사용이 불가능한 메소드입니다.");
		}

		/// <summary>
		/// MemoryStream.EndWrite 메소드를 재정의하여 아무것도 하지 않도록 합니다.
		/// </summary>
		public override void EndWrite(IAsyncResult asyncResult)
		{
			throw new InvalidOperationException("사용이 불가능한 메소드입니다.");
		}

		/// <summary>
		/// MemoryStream.FlushAsync 메소드를 재정의하여 아무것도 하지 않도록 합니다.
		/// </summary>
		public override Task FlushAsync(CancellationToken cancellationToken)
		{
			throw new InvalidOperationException("사용이 불가능한 메소드입니다.");
		}

		/// <summary>
		/// MemoryStream.ReadAsync 메소드를 재정의하여 아무것도 하지 않도록 합니다.
		/// </summary>
		public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
		{
			throw new InvalidOperationException("사용이 불가능한 메소드입니다.");
		}

		/// <summary>
		/// MemoryStream.CopyToAsync 메소드를 재정의하여 아무것도 하지 않도록 합니다.
		/// </summary>
		public override Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken)
		{
			throw new InvalidOperationException("사용이 불가능한 메소드입니다.");
		}

		/// <summary>
		/// MemoryStream.WriteAsync 메소드를 재정의하여 아무것도 하지 않도록 합니다.
		/// </summary>
		public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
		{
			throw new InvalidOperationException("사용이 불가능한 메소드입니다.");
		}
	}
}
