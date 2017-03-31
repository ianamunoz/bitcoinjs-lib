'use strict'

var typeforce = require('typeforce')
var types = require('../types')

var SHA256Compress = require('./sha256compress')

function PRF (a, b, c, d, x, y) {
  typeforce(types.tuple(
    types.BoolNum,
    types.BoolNum,
    types.BoolNum,
    types.BoolNum,
    types.Buffer252bit,
    types.Buffer256bit
  ), arguments)

  var blob = new Buffer(64)

  x.copy(blob, 0)
  y.copy(blob, 32)

  blob[0] &= 0x0F
  blob[0] |= (a ? 1 << 7 : 0) | (b ? 1 << 6 : 0) | (c ? 1 << 5 : 0) | (d ? 1 << 4 : 0)

  var hasher = new SHA256Compress()
  hasher.update(blob)
  return hasher.hash()
}

function PRF_addr (a_sk, t) {
  typeforce(types.tuple(types.Buffer252bit, types.UInt8), arguments)

  var y = new Buffer(32)
  y.fill(0)
  y[0] = t

  return PRF(1, 1, 0, 0, a_sk, y)
}

function PRF_addr_a_pk (a_sk) {
  return PRF_addr(a_sk, 0)
}

function PRF_addr_sk_enc (a_sk) {
  return PRF_addr(a_sk, 1)
}

function PRF_nf (a_sk, rho) {
  return PRF(1, 1, 1, 0, a_sk, rho)
}

function PRF_pk (a_sk, i0, h_sig) {
  typeforce(types.tuple(
    types.Buffer252bit,
    types.Number,
    types.Buffer256bit
  ), arguments)

  if ((i0 !== 0) && (i0 !== 1)) {
    throw new Error('PRF_pk invoked with index out of bounds')
  }

  return PRF(0, i0, 0, 0, a_sk, h_sig)
}

function PRF_rho (phi, i0, h_sig) {
  typeforce(types.tuple(
    types.Buffer252bit,
    types.Number,
    types.Buffer256bit
  ), arguments)

  if ((i0 !== 0) && (i0 !== 1)) {
    throw new Error('PRF_rho invoked with index out of bounds')
  }

  return PRF(0, i0, 1, 0, phi, h_sig)
}

module.exports = {
  PRF_addr_a_pk: PRF_addr_a_pk,
  PRF_addr_sk_enc: PRF_addr_sk_enc,
  PRF_nf: PRF_nf,
  PRF_pk: PRF_pk,
  PRF_rho: PRF_rho
}
