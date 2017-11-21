'use strict';
const fc = require('../lib/file-crypt');

// Encrypting file
{
  const filename = 'example.txt';
  const password = 'password';
  const extension = '.encrypt';
  const cipher = 'aes-256-cbc';
  const hash = 'sha256';

  fc.encryptFile(filename, password, extension, cipher, hash);
}

// Decrypting file
// {
//   const filename = 'example.txt.encrypt:83';
//   const password = 'password';

//   fc.decryptFile(filename, password);
// }
