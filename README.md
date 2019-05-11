# SecureStream
Provide CTR based simple AES encryption/decryption stream.

# Using

## Basic methods
```csharp
  // This method same as MemoryStream class methods. //
  CryptoMemoryStream.Write
  CryptoMemoryStream.Read
  
  // Encrypts and writes bytes to the stream. //
  CryptoMemoryStream.Encrypt
  
  // Decrypts and reading bytes from stream. //
  CryptoMemoryStream.Decrypt
```
## Notes ##
These methods do not reuse the nonce used in the CTR algorithm. That is, the result of encrypting all the bytes at once by the Write method differs from the result of encrypting the bytes by dividing them many times.

## Encryption
```csharp
  byte[] datas = new byte[] {0x00, 0x00, 0x00, 0x00};
  byte[] buffer = new byte[datas.Length];
  
  // Encrypt bytes //
  CryptoMemoryStream.Encrypt(datas, 0, datas.Length);
  
  // Reading encrypted bytes //
  // The CTR-based AES encryption algorithm has the same length as the original data length and the encrypted data. //
  // 0x00, 0x00, 0x00, 0x00 => 0x??, 0x??, 0x??, 0x??
  CryptoMemoryStream.Read(buffer, 0, buffer.Length);
```

## Decryption
```csharp
  byte[] encryptedDatas = new byte[] {0x??, 0x??, 0x??, 0x??};
  byte[] buffer = new byte[encryptedDatas.Length];
  
  // Decrypt bytes //
  CryptoMemoryStream.Write(encryptedDatas, 0, encryptedDatas.Length);
  
  // Reading dencrypted bytes //
  CryptoMemoryStream.Decrypt(buffer, 0, buffer.Length);
```
