'use strict'

var blake2b = require('./blake2b')
var libsodium = require('libsodium-sumo')

function KDF (dhsecret, epk, pk_enc, hSig, nonce) {
  if (nonce === 0xff) {
    throw new Error('no additional nonce space for KDF')
  }

  var block = new Uint8Array(128)
  hSig.copy(block, 0)
  dhsecret.copy(block, 32)
  epk.copy(block, 64)
  pk_enc.copy(block, 96)

  var personalization = new Uint8Array(libsodium._crypto_generichash_blake2b_personalbytes()).fill(0)
  new Buffer('ZcashKDF').copy(personalization, 0)
  personalization[8] = nonce

  return new Buffer(blake2b.crypto_generichash_blake2b_salt_personal(
    32,
    block,
    undefined, // No key.
    undefined, // No salt.
    personalization))
}

module.exports = KDF
