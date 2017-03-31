/* global describe, it */
'use strict'

var assert = require('assert')

var prf = require('../../src/zcash/prf')

var fixtures = require('../fixtures/zcash/prf')

describe('PRF', function () {
  describe('PRF_addr_a_pk', function () {
    fixtures.PRF_addr_a_pk.forEach(function (f) {
      it('calculates ' + f.hex + ' correctly', function () {
        var a_sk = new Buffer(f.a_sk, 'hex')
        assert.strictEqual(prf.PRF_addr_a_pk(a_sk).toString('hex'), f.hex)
      })
    })
  })

  describe('PRF_addr_sk_enc', function () {
    fixtures.PRF_addr_sk_enc.forEach(function (f) {
      it('calculates ' + f.hex + ' correctly', function () {
        var a_sk = new Buffer(f.a_sk, 'hex')
        assert.strictEqual(prf.PRF_addr_sk_enc(a_sk).toString('hex'), f.hex)
      })
    })
  })

  describe('PRF_nf', function () {
    fixtures.PRF_nf.forEach(function (f) {
      it('calculates ' + f.hex + ' correctly', function () {
        var a_sk = new Buffer(f.a_sk, 'hex')
        var rho = new Buffer(f.rho, 'hex')
        assert.strictEqual(prf.PRF_nf(a_sk, rho).toString('hex'), f.hex)
      })
    })
  })

  describe('PRF_pk', function () {
    fixtures.PRF_pk.forEach(function (f) {
      describe('a_sk [' + f.a_sk + ']', function () {
        var a_sk = new Buffer(f.a_sk, 'hex')
        var hSig = new Buffer(f.hSig, 'hex')
        f.hex.forEach(function (f, i) {
          it('calculates ' + i + ' correctly', function () {
            assert.strictEqual(prf.PRF_pk(a_sk, i, hSig).toString('hex'), f)
          })
        })
      })
    })
  })

  describe('PRF_rho', function () {
    fixtures.PRF_rho.forEach(function (f) {
      describe('phi [' + f.phi + ']', function () {
        var phi = new Buffer(f.phi, 'hex')
        var hSig = new Buffer(f.hSig, 'hex')
        f.hex.forEach(function (f, i) {
          it('calculates ' + i + ' correctly', function () {
            assert.strictEqual(prf.PRF_rho(phi, i, hSig).toString('hex'), f)
          })
        })
      })
    })
  })
})
