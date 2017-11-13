'use strict';

const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const extension = '.enc'; // string, extension of encrypted file
const algorithm = 'aes256'; // string, Name of encryption Algorithm
const hashAlorithm = 'sha256'; //string, Name of hash Algorithm
const iterations = 100000; // number, number of PBKDF2 iterations

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
  const lastFileName = filename + extension;

  const salt = createSalt();
  const key = crypto.pbkdf2Sync(password, salt, iterations, 64, hashAlorithm);
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
  const lastFileName = path.basename(filename, extension);

  let salt = '';
  const stream = fs.createReadStream(filename, { start: 0, end: 63 });
  stream.on('data', data => salt += data);
  stream.on('end', () => {

    const key = crypto.pbkdf2Sync(password, salt, iterations, 64, hashAlorithm);
    const cipher = crypto.createDecipher(algorithm, key);

    const input = fs.createReadStream(filename, { start: 64 });
    const output = fs.createWriteStream(lastFileName);

    input.pipe(cipher).pipe(output);
  });
};

module.exports = {
  encryptFile,
  decryptFile
};

