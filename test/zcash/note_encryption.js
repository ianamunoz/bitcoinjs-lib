/* global describe, it */
'use strict'

var assert = require('assert')

var ZCNoteDecryption = require('../../src/zcash/note_decryption')
var ZCNoteEncryption = require('../../src/zcash/note_encryption')

var zconst = require('../../src/zcash/const')
var zutil = require('../../src/zcash/util')

describe('Note Encryption', function () {
  var sk_enc = zutil.generate_privkey([].reverse.call(new Buffer('21035d60bc1983e37950ce4803418a8fb33ea68d5b937ca382ecbae7564d6a07', 'hex')))
  var pk_enc = zutil.generate_pubkey(sk_enc)

  var hSig = zutil.random_uint256()
  var b = new ZCNoteEncryption(hSig)
  var message = new Buffer(zconst.ZC_NOTEPLAINTEXT_SIZE)
  for (let i = 0; i < zconst.ZC_NOTEPLAINTEXT_SIZE; ++i) {
    message[i] = i
  }

  for (let i = 0; i < 255; ++i) {
    var ciphertext
    var decrypter = new ZCNoteDecryption(sk_enc)

    it('correctly encrypts and decrypts nonce ' + i, function () {
      ciphertext = b.encrypt(pk_enc, message)
      var plaintext = decrypter.decrypt(ciphertext, b.epk, hSig, i)
      assert.strictEqual(plaintext.toString('hex'), message.toString('hex'))
    })

    it('fails to decrypt ' + i + ' with wrong nonce', function () {
      assert.throws(function () {
        decrypter.decrypt(ciphertext, b.epk, hSig, (i === 0) ? 1 : (i - 1))
      })
    })

    it('fails to decrypt ' + i + ' with wrong oneTimePubKey', function () {
      var c = new ZCNoteEncryption(hSig)
      assert.throws(function () {
        decrypter.decrypt(ciphertext, c.epk, hSig, i)
      })
    })

    it('fails to decrypt ' + i + ' with wrong seed', function () {
      assert.throws(function () {
        decrypter.decrypt(ciphertext, b.epk, [].reverse.call(new Buffer('11035d60bc1983e37950ce4803418a8fb33ea68d5b937ca382ecbae7564d6a77', 'hex')), i)
      })
    })

    it('fails to decrypt ' + i + ' with corrupted ciphertext', function () {
      ciphertext[10] ^= 0xff
      assert.throws(function () {
        decrypter.decrypt(ciphertext, b.epk, hSig, i)
      })
      ciphertext[10] ^= 0xff
    })

    it('fails to decrypt ' + i + ' with wrong private key', function () {
      var sk_enc_2 = zutil.generate_privkey(zutil.random_uint252())
      var decrypter2 = new ZCNoteDecryption(sk_enc_2)
      assert.throws(function () {
        decrypter2.decrypt(ciphertext, b.epk, hSig, i)
      })
    })

    it('fails to decrypt ' + i + ' with wrong public key (test of KDF)', function () {
      var decrypter2 = new ZCNoteDecryption(sk_enc)
      decrypter2.pk_enc = zutil.generate_pubkey(zutil.random_uint256())
      assert.throws(function () {
        decrypter2.decrypt(ciphertext, b.epk, hSig, i)
      })
    })
  }

  it('runs out of nonce space with nonce 255', function () {
    assert.throws(function () {
      b.encrypt(pk_enc, message)
    }, new RegExp('no additional nonce space for KDF'))
  })
})
