#!/usr/bin/env node
'use strict';

const fc = require('../lib/file-crypt');

const command = (process.argv[2] || '').toLowerCase();
const password = 'password';

if (command === '-e') {
  // Encrypting file
  const filename = 'example.txt';
  const extension = '.encrypt';
  const cipher = 'aes-256-cbc';
  const hash = 'sha256';
  fc.encryptFile(filename, password, extension, cipher, hash);
} else if (command === '-d') {
  // Decrypting file
  const filename = 'example.txt.encrypt:83';
  const password = 'password';
  fc.decryptFile(filename, password);
} else {
  console.log('Usage: ');
  console.log('  - encrypt file: ./example.js -e');
  console.log('  - decrypt file: ./example.js -d');
}
