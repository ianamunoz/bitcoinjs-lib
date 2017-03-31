'use strict'

var bufferutils = require('../bufferutils')

var SHA256Compress = require('./sha256compress')

var INCREMENTAL_MERKLE_TREE_DEPTH = 29

function combine (left, right) {
  var hasher = new SHA256Compress()
  hasher.update(left)
  hasher.update(right)
  return hasher.hash()
}

function ZCIncrementalMerkleTree () {
  this.left = null
  this.right = null
  this.parents = []
}

ZCIncrementalMerkleTree.fromBuffer = function (buffer, __noStrict) {
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

  function readOptionalSlice (n) {
    var i = readUInt8()
    if (i === 1) {
      return readSlice(n)
    } else if (i === 0) {
      return null
    } else {
      throw new Error('Invalid optional')
    }
  }

  var tree = new ZCIncrementalMerkleTree()
  tree.left = readOptionalSlice(32)
  tree.right = readOptionalSlice(32)

  var parentsLen = readVarInt()
  for (var i = 0; i < parentsLen; ++i) {
    tree.parents.push(readOptionalSlice(32))
  }

  if (__noStrict) return tree
  if (offset !== buffer.length) throw new Error('ZCIncrementalMerkleTree has unexpected data')

  return tree
}

ZCIncrementalMerkleTree.prototype.byteLength = function () {
  return (
    (this.left ? 33 : 1) +
    (this.right ? 33 : 1) +
    bufferutils.varIntSize(this.parents.length) +
    this.parents.reduce(function (sum, hash) { return sum + (hash ? 33 : 1) }, 0)
  )
}

ZCIncrementalMerkleTree.prototype.toBuffer = function () {
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

  function writeOptionalSlice (val) {
    if (val) {
      writeUInt8(1)
      writeSlice(val)
    } else {
      writeUInt8(0)
    }
  }

  writeOptionalSlice(this.left)
  writeOptionalSlice(this.right)

  writeVarInt(this.parents.length)
  this.parents.forEach(function (hash) {
    writeOptionalSlice(hash)
  })

  return buffer
}

ZCIncrementalMerkleTree.prototype.append = function (obj) {
  if (this.is_complete(INCREMENTAL_MERKLE_TREE_DEPTH)) {
    throw new Error('tree is full')
  }

  if (!this.left) {
    // Set the left leaf
    this.left = obj
  } else if (!this.right) {
    // Set the right leaf
    this.right = obj
  } else {
    // Combine the leaves and propagate it up the tree
    var combined = combine(this.left, this.right)

    // Set the "left" leaf to the object and make the "right" leaf null
    this.left = obj
    this.right = null

    for (var i = 0; i < INCREMENTAL_MERKLE_TREE_DEPTH; i++) {
      if (i < this.parents.size()) {
        if (this.parents[i]) {
          combined = combine(this.parents[i], combined)
          this.parents[i] = null
        } else {
          this.parents[i] = combined
          break
        }
      } else {
        this.parents.push(combined)
        break
      }
    }
  }
}

// This is for allowing the witness to determine if a subtree has filled
// to a particular depth, or for append() to ensure we're not appending
// to a full tree.
ZCIncrementalMerkleTree.prototype.is_complete = function (depth) {
  if (!this.left || !this.right) {
    return false
  }

  if (this.parents.size() !== (depth - 1)) {
    return false
  }

  this.parents.forEach(function (parent) {
    if (!parent) {
      return false
    }
  })

  return true
}

module.exports = ZCIncrementalMerkleTree
