'use strict';
var crypto = require('crypto');
var fs = require('fs');
var path = require('path');

var ALGO = 'aes-256-gcm';

function deriveKey(passphrase) {
  return crypto.createHash('sha256').update(String(passphrase)).digest();
}

// Encrypt a file in place -> outputs filePath + '.enc', removes plaintext
function encryptFile(filePath, passphrase) {
  if (!fs.existsSync(filePath)) throw new Error('File not found: ' + filePath);
  var key = deriveKey(passphrase);
  var iv = crypto.randomBytes(16);
  var cipher = crypto.createCipheriv(ALGO, key, iv);

  var input = fs.readFileSync(filePath);
  var encrypted = Buffer.concat([cipher.update(input), cipher.final()]);
  var authTag = cipher.getAuthTag();

  var outPath = filePath + '.enc';
  // Format: [16-byte IV][16-byte authTag][ciphertext]
  fs.writeFileSync(outPath, Buffer.concat([iv, authTag, encrypted]));
  fs.unlinkSync(filePath);
  return outPath;
}

// Decrypt a .enc file -> outputs original path
function decryptFile(encFilePath, passphrase) {
  if (!fs.existsSync(encFilePath)) throw new Error('File not found: ' + encFilePath);
  var key = deriveKey(passphrase);
  var data = fs.readFileSync(encFilePath);

  var iv = data.slice(0, 16);
  var authTag = data.slice(16, 32);
  var ciphertext = data.slice(32);

  var decipher = crypto.createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(authTag);
  var decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

  var outPath = encFilePath.replace(/\.enc$/, '');
  fs.writeFileSync(outPath, decrypted);
  return outPath;
}

// Encrypt an entire directory's files recursively (for IFM folders etc.)
function encryptDirectory(dirPath, passphrase) {
  var results = [];
  function walk(dir) {
    var entries = fs.readdirSync(dir, { withFileTypes: true });
    entries.forEach(function(entry) {
      var full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (!entry.name.endsWith('.enc')) {
        try { results.push(encryptFile(full, passphrase)); } catch(e) {}
      }
    });
  }
  walk(dirPath);
  return results;
}

module.exports = { encryptFile, decryptFile, encryptDirectory, deriveKey };
