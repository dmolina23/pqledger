// Example: Fabric chaincode (Node.js). Scanner input only.
'use strict';

const { Contract } = require('fabric-contract-api');
const crypto = require('crypto');
const EC = require('elliptic').ec;

class AssetContract extends Contract {
  async newKey() {
    return crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
    });
  }

  async digest(data) {
    return crypto.createHash('sha1').update(data).digest('hex');
  }

  async sign(data, key) {
    return crypto.createSign('RSA-SHA256').update(data).sign(key);
  }

  async chainKey() {
    return new EC('secp256k1').genKeyPair();
  }
}

module.exports = AssetContract;
