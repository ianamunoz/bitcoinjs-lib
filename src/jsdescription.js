'use strict'

var blake2b = require('./zcash/blake2b')
var bufferutils = require('./bufferutils')
var prf = require('./zcash/prf')
var typeforce = require('typeforce')
var types = require('./types')
var zconst = require('./zcash/const')
var zutil = require('./zcash/util')

var JSProofWitness = require('./zcash/proof_witness')
var NotePlaintext = require('./zcash/note_plaintext')
var ZCNoteEncryption = require('./zcash/note_encryption')
var ZCProof = require('./zcash/proof')

function h_sig (randomSeed, nullifiers, pubKeyHash) {
  typeforce(types.tuple(
    types.Buffer256bit,
    types.arrayOf(types.Hash256bit),
    types.Hash256bit
  ), arguments)

  return new Buffer(blake2b.crypto_generichash_blake2b_salt_personal(
    32,
    Buffer.concat([randomSeed].concat(nullifiers).concat([pubKeyHash])),
    undefined, // No key.
    undefined, // No salt.
    'ZcashComputehSig'))
}

function JSDescription () {
  this.nullifiers = []
  this.commitments = []
  this.ciphertexts = []
  this.macs = []
}

JSDescription.fromBuffer = function (buffer, __noStrict) {
  var offset = 0
  function readSlice (n) {
    offset += n
    return buffer.slice(offset - n, offset)
  }

  function readUInt64 () {
    var i = bufferutils.readUInt64LE(buffer, offset)
    offset += 8
    return i
  }

  function readZCProof () {
    var proof = ZCProof.fromBuffer(buffer.slice(offset), true)
    offset += proof.byteLength()
    return proof
  }

  var jsdesc = new JSDescription()
  jsdesc.vpub_old = readUInt64()
  jsdesc.vpub_new = readUInt64()
  jsdesc.anchor = readSlice(32)

  for (var i = 0; i < zconst.ZC_NUM_JS_INPUTS; ++i) {
    jsdesc.nullifiers.push(readSlice(32))
  }

  for (i = 0; i < zconst.ZC_NUM_JS_OUTPUTS; ++i) {
    jsdesc.commitments.push(readSlice(32))
  }

  jsdesc.onetimePubKey = readSlice(32)
  jsdesc.randomSeed = readSlice(32)

  for (i = 0; i < zconst.ZC_NUM_JS_INPUTS; ++i) {
    jsdesc.macs.push(readSlice(32))
  }

  jsdesc.proof = readZCProof()

  for (i = 0; i < zconst.ZC_NUM_JS_OUTPUTS; ++i) {
    jsdesc.ciphertexts.push(readSlice(zconst.ZC_NOTECIPHERTEXT_SIZE))
  }

  if (__noStrict) return jsdesc
  if (offset !== buffer.length) throw new Error('JSDescription has unexpected data')

  return jsdesc
}

JSDescription.fromHex = function (hex) {
  return JSDescription.fromBuffer(new Buffer(hex, 'hex'))
}

JSDescription.prototype.byteLength = function () {
  return (
    112 +
    zconst.ZC_NUM_JS_INPUTS * 64 +
    zconst.ZC_NUM_JS_OUTPUTS * (32 + zconst.ZC_NOTECIPHERTEXT_SIZE) +
    this.proof.byteLength()
  )
}

JSDescription.prototype.clone = function () {
  var newJSDesc = new JSDescription()
  newJSDesc.vpub_old = this.vpub_old
  newJSDesc.vpub_new = this.vpub_new
  newJSDesc.anchor = this.anchor

  newJSDesc.nullifiers = this.nullifiers.map(function (nullifier) {
    return nullifier
  })

  newJSDesc.commitments = this.commitments.map(function (commitment) {
    return commitment
  })

  newJSDesc.onetimePubKey = this.onetimePubKey
  newJSDesc.randomSeed = this.randomSeed

  newJSDesc.macs = this.macs.map(function (mac) {
    return mac
  })

  newJSDesc.proof = this.proof.clone()

  newJSDesc.ciphertexts = this.ciphertexts.map(function (ciphertext) {
    return ciphertext
  })

  return newJSDesc
}

JSDescription.prototype.toBuffer = function () {
  var buffer = new Buffer(this.byteLength())

  var offset = 0
  function writeSlice (slice) {
    slice.copy(buffer, offset)
    offset += slice.length
  }

  function writeUInt64 (i) {
    bufferutils.writeUInt64LE(buffer, i, offset)
    offset += 8
  }

  writeUInt64(this.vpub_old)
  writeUInt64(this.vpub_new)
  writeSlice(this.anchor)

  this.nullifiers.forEach(function (nullifier) {
    writeSlice(nullifier)
  })

  this.commitments.forEach(function (commitment) {
    writeSlice(commitment)
  })

  writeSlice(this.onetimePubKey)
  writeSlice(this.randomSeed)

  this.macs.forEach(function (mac) {
    writeSlice(mac)
  })

  writeSlice(this.proof.toBuffer())

  this.ciphertexts.forEach(function (ciphertext) {
    writeSlice(ciphertext)
  })

  return buffer
}

JSDescription.prototype.toHex = function () {
  return this.toBuffer().toString('hex')
}

JSDescription.prototype.h_sig = function (joinSplitPubKey) {
  return h_sig(this.randomSeed, this.nullifiers, joinSplitPubKey)
}

JSDescription.withWitness = function (inputs, outputs, pubKeyHash, vpub_old, vpub_new, rt) {
  typeforce(types.tuple(
    types.arrayOf(types.JSInput),
    types.arrayOf(types.JSOutput),
    types.Hash256bit,
    types.UInt53,
    types.UInt53,
    types.Hash256bit
  ), arguments)

  if (inputs.length !== zconst.ZC_NUM_JS_INPUTS) {
    throw new Error(`invalid number of inputs (found ${inputs.length}, expected ${zconst.ZC_NUM_JS_INPUTS}`)
  }
  if (outputs.length !== zconst.ZC_NUM_JS_OUTPUTS) {
    throw new Error(`invalid number of inputs (found ${outputs.length}, expected ${zconst.ZC_NUM_JS_OUTPUTS}`)
  }

  var jsdesc = new JSDescription()
  jsdesc.vpub_old = vpub_old
  jsdesc.vpub_new = vpub_new
  jsdesc.anchor = rt

  var lhs_value = vpub_old
  var rhs_value = vpub_new

  inputs.forEach(function (input) {
    // Sanity checks of input

    // If note has nonzero value
    if (input.note.value !== 0) {
      // The witness root must equal the input root.
      if (input.witness.root() !== rt) {
        throw new Error('joinsplit not anchored to the correct root')
      }

      // The tree must witness the correct element
      if (input.note.cm() !== input.witness.element()) {
        throw new Error('witness of wrong element for joinsplit input')
      }
    }

    // Ensure we have the key to this note.
    if (input.note.a_pk.toString('hex') !== input.key.address().a_pk.toString('hex')) {
      throw new Error('input note not authorized to spend with given key')
    }

    // Balance must be sensical
    typeforce(types.UInt53, input.note.value)
    lhs_value += input.note.value
    typeforce(types.UInt53, lhs_value)

    // Compute nullifier of input
    jsdesc.nullifiers.push(input.nullifier())
  })

  // Sample randomSeed
  jsdesc.randomSeed = zutil.random_uint256()

  // Compute h_sig
  var hSig = jsdesc.h_sig(pubKeyHash)

  // Sample phi
  var phi = zutil.random_uint252()

  // Compute notes for outputs
  var notes = []
  outputs.forEach(function (output, i) {
    // Sanity checks of output
    typeforce(types.UInt53, output.value)
    rhs_value += output.value
    typeforce(types.UInt53, rhs_value)

    // Sample r
    var r = zutil.random_uint256()

    notes.push(output.note(phi, r, i, hSig))
  })

  if (lhs_value !== rhs_value) {
    throw new Error('invalid joinsplit balance')
  }

  // Compute the output commitments
  notes.forEach(function (note) {
    jsdesc.commitments.push(note.cm())
  })

  // Encrypt the ciphertexts containing the note
  // plaintexts to the recipients of the value.
  var encryptor = new ZCNoteEncryption(hSig)

  notes.forEach(function (note, i) {
    var pt = new NotePlaintext(note, outputs[i].memo)

    jsdesc.ciphertexts.push(pt.encrypt(encryptor, outputs[i].addr.pk_enc))
  })

  jsdesc.ephemeralKey = encryptor.epk

  // Authenticate hSig with each of the input
  // spending keys, producing macs which protect
  // against malleability.
  inputs.forEach(function (input, i) {
    jsdesc.macs.push(prf.PRF_pk(inputs[i].key.a_sk, i, hSig))
  })

  jsdesc.witness = new JSProofWitness(phi, rt, hSig, inputs, notes, vpub_old, vpub_new)

  return jsdesc
}

module.exports = JSDescription
