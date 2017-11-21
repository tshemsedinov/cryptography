'use strict';

const fs = require('fs');
const crypto = require('crypto');

const ext = '.enc'; // string, extension of encrypted file
const algorithm = 'aes256'; // string, Name of encryption Algorithm
const hashAlorithm = 'sha256'; //string, Name of hash Algorithm
const num = 100000; // number, number of PBKDF2 iterations

const createSalt = () => {
  const hash = crypto.createHash(hashAlorithm);
  const random = Math.floor(Math.random() * (100000)).toString();
  return hash.update(random).digest('hex');
};

const encryptFile = (
  // Function for encrypting a file
  filename, // string, Full name of the file for encryption
  password // string, String of any length
) => {
  if (!fs.existsSync(filename)) throw new Error('File not found.');
  const lastFileName = filename + ext;

  const salt = createSalt();
  const key = crypto.pbkdf2Sync(password, salt, num, 64, hashAlorithm);
  const cipher = crypto.createCipher(algorithm, key);

  const input = fs.createReadStream(filename);
  const output = fs.createWriteStream(lastFileName, { flags: 'a' });

  fs.writeFileSync(lastFileName, salt, 'utf-8');
  input.pipe(cipher).pipe(output);
};

const decryptFile = (
  // Function for decrypting a file
  filename, // string, Full name of the file for decryption
  password // string, String of any length
) => {
  if (!fs.existsSync(filename)) throw new Error('File not found.');
  const lastFileName = filename.substring(0, filename.length - ext.length);
  const stream = fs.createReadStream(filename);

  const reader = () => {
    stream.removeListener('readable', reader);
    const salt = stream.read(64).toString();
    const key = crypto.pbkdf2Sync(password, salt, num, 64, hashAlorithm);
    const cipher = crypto.createDecipher(algorithm, key);
    const output = fs.createWriteStream(lastFileName);
    stream.pipe(cipher).pipe(output);
  };

  stream.on('readable', reader);
};

module.exports = {
  encryptFile,
  decryptFile
};
