'use strict'

var sodium = require('libsodium-wrappers-sumo')
var typeforce = require('typeforce')
var types = require('../types')
var zutil = require('./util')

var KDF = require('./kdf')

function ZCNoteEncryption (hSig) {
  typeforce(types.Hash256bit, hSig)

  this.nonce = 0
  this.hSig = hSig
  this.esk = zutil.random_uint256()
  this.epk = zutil.generate_pubkey(this.esk)
}

ZCNoteEncryption.prototype.encrypt = function (pk_enc, message) {
  typeforce(types.tuple(
    types.Buffer256bit,
    types.Buffer
  ), arguments)

  var dhsecret = new Buffer(sodium.crypto_scalarmult(this.esk, pk_enc))

  // Construct the symmetric key
  var K = KDF(dhsecret, this.epk, pk_enc, this.hSig, this.nonce)

  // Increment the number of encryptions we've performed
  this.nonce++

  // The nonce is zero because we never reuse keys
  var cipher_nonce = new Uint8Array(sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES)
  sodium.memzero(cipher_nonce)

  return new Buffer(sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
      message, null, null, cipher_nonce, K))
}

module.exports = ZCNoteEncryption
