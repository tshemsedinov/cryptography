'use strict';

const fs = require('fs');
const crypto = require('crypto');

const PBKDF2_COUNT = 100000; // number, number of PBKDF2 iterations
const KEY_LENGTH = 64;
const HEADER_LENGTH = 83;

const ciphers = crypto.getCiphers(); // array, List of all ciphers
const hashes = crypto.getHashes(); // array, List of all hashes

const createSalt = (hash) => {
  const createHash = crypto.createHash(hash);
  const random = crypto.randomBytes(64).toString();
  return createHash.update(random).digest('hex');
};

const encryptFile = (
  // Function for encrypting a file
  filename, // string, Full name of the file for encryption
  password, // string, String of any length
  ext = '.enc', // string, extension of encrypted file
  cipher = 'aes-256-cbc', // string, Name of encryption algorithm
  hash = 'sha256', // string, Name of hash algorithm
  callback // on done
) => {
  if (!fs.existsSync(filename)) throw new Error('File not found');
  if (!password) throw new Error('Password not found');
  if (!hashes.includes(hash)) throw new Error('Hash not found');
  if (!ciphers.includes(cipher)) throw new Error('Cipher not found');

  if (ext[0] !== '.') ext = '.' + ext;
  const lastFileName = filename + ext;

  const salt = createSalt(hash);
  const key = crypto.pbkdf2Sync(
    password, salt, PBKDF2_COUNT, KEY_LENGTH, hash
  );
  const cipherStream = crypto.createCipher(cipher, key);

  const input = fs.createReadStream(filename);
  const output = fs.createWriteStream(lastFileName);

  const header = [salt, cipher, hash].join('|');

  output.write(header);
  input.pipe(cipherStream).pipe(output);
  fs.renameSync(lastFileName, lastFileName);
};

const decryptFile = (
  // Function for decrypting a file
  filename, // string, Full name of the file for decryption
  password, // string, String of any length
  callback // on done
) => {
  if (!fs.existsSync(filename)) throw new Error('File not found');

  const ext = '.' + filename.split('.').pop();
  const lastFileName = filename.substring(0, filename.length - ext.length);
  const stream = fs.createReadStream(filename);

  const reader = () => {
    stream.removeListener('readable', reader);
    const header = stream.read(HEADER_LENGTH).toString();
    const [salt, cipher, hash] = header.split('|');

    if (!hashes.includes(hash)) throw new Error('Hash not found');
    if (!ciphers.includes(cipher)) throw new Error('Cipher not found');

    const key = crypto.pbkdf2Sync(
      password, salt, PBKDF2_COUNT, KEY_LENGTH, hash
    );
    const cipherStream = crypto.createDecipher(cipher, key);
    const output = fs.createWriteStream(lastFileName);
    stream.pipe(cipherStream).pipe(output);
  };

  stream.on('readable', reader);
};

module.exports = {
  encryptFile,
  decryptFile,
};

