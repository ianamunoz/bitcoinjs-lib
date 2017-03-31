'use strict'

var bufferutils = require('../bufferutils')

var ZCIncrementalMerkleTree = require('./incremental_merkle_tree')

function ZCIncrementalWitness () {
  this.tree = new ZCIncrementalMerkleTree()
  this.filled = []
  this.cursor = null
}

ZCIncrementalWitness.fromTree = function (tree) {
  var witness = new ZCIncrementalWitness()
  witness.tree = tree
  return witness
}

ZCIncrementalWitness.fromBuffer = function (buffer, __noStrict) {
  var offset = 0
  function readSlice (n) {
    offset += n
    return buffer.slice(offset - n, offset)
  }

  function readUInt8 () {
    var i = buffer.readUInt8(offset)
    offset += 1
    return i
  }

  function readVarInt () {
    var vi = bufferutils.readVarInt(buffer, offset)
    offset += vi.size
    return vi.number
  }

  function readOptional (func) {
    var i = readUInt8()
    if (i === 1) {
      return func()
    } else if (i === 0) {
      return null
    } else {
      throw new Error('Invalid optional')
    }
  }

  function readZCIncrementalMerkleTree () {
    var tree = ZCIncrementalMerkleTree.fromBuffer(buffer.slice(offset), true)
    offset += tree.byteLength()
    return tree
  }

  var witness = new ZCIncrementalWitness()
  witness.tree = readZCIncrementalMerkleTree()

  var filledLen = readVarInt()
  for (var i = 0; i < filledLen; ++i) {
    witness.filled.push(readSlice(32))
  }

  witness.cursor = readOptional(readZCIncrementalMerkleTree)

  if (__noStrict) return witness
  if (offset !== buffer.length) throw new Error('ZCIncrementalWitness has unexpected data')

  return witness
}

ZCIncrementalWitness.prototype.byteLength = function () {
  return (
    this.tree.byteLength() +
    bufferutils.varIntSize(this.filled.length) +
    this.filled.length * 32 +
    (this.cursor ? this.cursor.byteLength() + 1 : 1)
  )
}

ZCIncrementalWitness.prototype.toBuffer = function () {
  var buffer = new Buffer(this.byteLength())

  var offset = 0
  function writeSlice (slice) {
    slice.copy(buffer, offset)
    offset += slice.length
  }

  function writeUInt8 (i) {
    buffer.writeUInt8(i, offset)
    offset += 1
  }

  function writeVarInt (i) {
    var n = bufferutils.writeVarInt(buffer, i, offset)
    offset += n
  }

  function writeOptional (val, func) {
    if (val) {
      writeUInt8(1)
      func(val)
    } else {
      writeUInt8(0)
    }
  }

  function writeZCIncrementalMerkleTree (tree) {
    writeSlice(tree.toBuffer())
  }

  writeSlice(this.tree.toBuffer())

  writeVarInt(this.filled.length)
  this.filled.forEach(function (hash) {
    writeSlice(hash)
  })

  writeOptional(this.cursor, writeZCIncrementalMerkleTree)

  return buffer
}

module.exports = ZCIncrementalWitness
