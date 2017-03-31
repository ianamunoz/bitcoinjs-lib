/* global describe, it, beforeEach */

var assert = require('assert')

var JSDescription = require('../src/jsdescription')
var ZCProof = require('../src/zcash/proof')

var fixtures = require('./fixtures/jsdescription')
var hSigFixtures = require('./fixtures/hsig')

describe('JSDescription', function () {
  function fromRaw (raw) {
    var jsdesc = new JSDescription()
    jsdesc.vpub_old = raw.vpub_old
    jsdesc.vpub_new = raw.vpub_new
    jsdesc.anchor = [].reverse.call(new Buffer(raw.anchor, 'hex'))

    raw.nullifiers.forEach(function (nullifier) {
      jsdesc.nullifiers.push([].reverse.call(new Buffer(nullifier, 'hex')))
    })

    raw.commitments.forEach(function (commitment) {
      jsdesc.commitments.push([].reverse.call(new Buffer(commitment, 'hex')))
    })

    jsdesc.onetimePubKey = [].reverse.call(new Buffer(raw.onetimePubKey, 'hex'))
    jsdesc.randomSeed = [].reverse.call(new Buffer(raw.randomSeed, 'hex'))

    raw.macs.forEach(function (mac) {
      jsdesc.macs.push([].reverse.call(new Buffer(mac, 'hex')))
    })

    jsdesc.proof = ZCProof.fromHex(raw.proof)

    raw.ciphertexts.forEach(function (ciphertext) {
      jsdesc.ciphertexts.push(new Buffer(ciphertext, 'hex'))
    })

    return jsdesc
  }

  describe('fromBuffer/fromHex', function () {
    fixtures.valid.forEach(function (f) {
      it('imports ' + f.description, function () {
        var actual = JSDescription.fromHex(f.hex)

        assert.strictEqual(actual.toHex(), f.hex, actual.toHex())
      })
    })

    fixtures.invalid.fromBuffer.forEach(function (f) {
      it('throws on ' + f.exception, function () {
        assert.throws(function () {
          JSDescription.fromHex(f.hex)
        }, new RegExp(f.exception))
      })
    })
  })

  describe('toBuffer/toHex', function () {
    fixtures.valid.forEach(function (f) {
      it('exports ' + f.description, function () {
        var actual = fromRaw(f.raw)

        assert.strictEqual(actual.toHex(), f.hex, actual.toHex())
      })
    })
  })

  describe('clone', function () {
    fixtures.valid.forEach(function (f) {
      var actual, expected

      beforeEach(function () {
        expected = JSDescription.fromHex(f.hex)
        actual = expected.clone()
      })

      it('should have value equality', function () {
        assert.deepEqual(actual, expected)
      })

      it('should not have reference equality', function () {
        assert.notEqual(actual, expected)
      })
    })
  })

  describe('hSig', function () {
    hSigFixtures.valid.forEach(function (f) {
      it('equals ' + f.hex, function () {
        var jsdesc = new JSDescription()
        jsdesc.randomSeed = [].reverse.call(new Buffer(f.randomSeed, 'hex'))
        f.nullifiers.forEach(function (nullifier) {
          jsdesc.nullifiers.push([].reverse.call(new Buffer(nullifier, 'hex')))
        })

        var actual = jsdesc.h_sig([].reverse.call(new Buffer(f.pubKeyHash, 'hex')))
        var expected = [].reverse.call(new Buffer(f.hex, 'hex'))
        assert.strictEqual(new Buffer(actual).toString('hex'), expected.toString('hex'))
      })
    })
  })
})
