'use strict'

var bs58check = require('bs58check')
var networks = require('../networks')
var prf = require('./prf')
var typeforce = require('typeforce')
var types = require('../types')
var zutil = require('./util')

function PaymentAddress (a_pk, pk_enc) {
  typeforce(types.tuple(types.Buffer256bit, types.Buffer256bit), arguments)
  this.a_pk = a_pk
  this.pk_enc = pk_enc
}

PaymentAddress.fromBuffer = function (buffer, __noStrict) {
  var offset = 0
  function readSlice (n) {
    offset += n
    return buffer.slice(offset - n, offset)
  }

  var a_pk = readSlice(32)
  var pk_enc = readSlice(32)
  var addr = new PaymentAddress(a_pk, pk_enc)

  if (__noStrict) return addr
  if (offset !== buffer.length) throw new Error('PaymentAddress has unexpected data')

  return addr
}

PaymentAddress.prototype.byteLength = function () {
  return 64
}

PaymentAddress.prototype.toBuffer = function () {
  var buffer = new Buffer(this.byteLength())

  var offset = 0
  function writeSlice (slice) {
    slice.copy(buffer, offset)
    offset += slice.length
  }

  writeSlice(this.a_pk)
  writeSlice(this.pk_enc)

  return buffer
}

function SpendingKey (a_sk) {
  typeforce(types.Buffer252bit, a_sk)
  this.a_sk = a_sk
}

SpendingKey.random = function () {
  return new SpendingKey(zutil.random_uint252())
}

SpendingKey.fromBuffer = function (buffer, __noStrict) {
  var offset = 0
  function readSlice (n) {
    offset += n
    return buffer.slice(offset - n, offset)
  }

  var a_sk = readSlice(32)
  var sk = new SpendingKey(a_sk)

  if (__noStrict) return sk
  if (offset !== buffer.length) throw new Error('SpendingKey has unexpected data')

  return sk
}

SpendingKey.prototype.byteLength = function () {
  return 32
}

SpendingKey.prototype.toBuffer = function () {
  var buffer = new Buffer(this.byteLength())

  var offset = 0
  function writeSlice (slice) {
    slice.copy(buffer, offset)
    offset += slice.length
  }

  writeSlice(this.a_sk)

  return buffer
}

SpendingKey.prototype.address = function () {
  return new PaymentAddress(
    prf.PRF_addr_a_pk(this.a_sk),
    zutil.generate_pubkey(zutil.generate_privkey(this.a_sk))
  )
}

function fromBase58Check (address) {
  var payload = bs58check.decode(address)
  if (payload.length < 66) throw new TypeError(address + ' is too short')
  if (payload.length > 66) throw new TypeError(address + ' is too long')

  var version = payload.readUInt16BE(0)
  var data = payload.slice(2)

  return { data: data, version: version }
}

function toPaymentAddress (address, network) {
  network = network || networks.zcash

  var decode = fromBase58Check(address)
  if (decode.version === network.zcPaymentAddress) return PaymentAddress.fromBuffer(decode.data)

  throw new Error(address + ' has no matching PaymentAddress')
}

module.exports = {
  PaymentAddress: PaymentAddress,
  SpendingKey: SpendingKey,
  fromBase58Check: fromBase58Check,
  toPaymentAddress: toPaymentAddress
}
