'use strict'

var sodium = require('libsodium-wrappers-sumo')
var typeforce = require('typeforce')
var types = require('../types')
var zutil = require('./util')

var KDF = require('./kdf')

function ZCNoteDecryption (sk_enc) {
  typeforce(types.Buffer256bit, sk_enc)

  this.sk_enc = sk_enc
  this.pk_enc = zutil.generate_pubkey(sk_enc)
}

ZCNoteDecryption.prototype.decrypt = function (ciphertext, epk, hSig, nonce) {
  typeforce(types.tuple(
    types.Buffer,
    types.Buffer256bit,
    types.Hash256bit,
    types.Number
  ), arguments)

  var dhsecret = new Buffer(sodium.crypto_scalarmult(this.sk_enc, epk))

  // Construct the symmetric key
  var K = KDF(dhsecret, epk, this.pk_enc, hSig, nonce)

  // The nonce is zero because we never reuse keys
  var cipher_nonce = new Uint8Array(sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES)
  sodium.memzero(cipher_nonce)

  return new Buffer(sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
      null, ciphertext, null, cipher_nonce, K))
}

module.exports = ZCNoteDecryption
