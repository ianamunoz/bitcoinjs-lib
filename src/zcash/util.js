'use strict'

var prf = require('./prf')
var sodium = require('libsodium-wrappers')
var typeforce = require('typeforce')
var types = require('../types')

function random_uint256 () {
  return new Buffer(sodium.randombytes_buf(32))
}

function random_uint252 () {
  var rand = new Buffer(random_uint256())
  rand[0] &= 0x0F
  return rand
}

function generate_privkey (a_sk) {
  var sk = prf.PRF_addr_sk_enc(a_sk)

  // Curve25519 clamping
  sk[0] &= 248
  sk[31] &= 127
  sk[31] |= 64

  return sk
}

function generate_pubkey (sk_enc) {
  typeforce(types.Buffer256bit, sk_enc)

  return new Buffer(sodium.crypto_scalarmult_base(sk_enc))
}

module.exports = {
  generate_privkey: generate_privkey,
  generate_pubkey: generate_pubkey,
  random_uint252: random_uint252,
  random_uint256: random_uint256
}
