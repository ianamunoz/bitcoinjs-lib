var bcrypto = require('./crypto')
var bscript = require('./script')
var bufferutils = require('./bufferutils')
var opcodes = require('./opcodes')
var sodium = require('libsodium-wrappers-sumo')
var typeforce = require('typeforce')
var types = require('./types')
var zmq = require('zeromq')

var JSDescription = require('./jsdescription')
var JSInput = require('./zcash/jsinput')
var JSOutput = require('./zcash/jsoutput')
var ZCProof = require('./zcash/proof')

function Transaction () {
  this.version = 1
  this.locktime = 0
  this.ins = []
  this.outs = []
  this.jss = []

  this._jsouts = []
}

Transaction.DEFAULT_SEQUENCE = 0xffffffff
Transaction.SIGHASH_ALL = 0x01
Transaction.SIGHASH_NONE = 0x02
Transaction.SIGHASH_SINGLE = 0x03
Transaction.SIGHASH_ANYONECANPAY = 0x80

Transaction.fromBuffer = function (buffer, __noStrict) {
  var offset = 0
  function readSlice (n) {
    offset += n
    return buffer.slice(offset - n, offset)
  }

  function readUInt32 () {
    var i = buffer.readUInt32LE(offset)
    offset += 4
    return i
  }

  function readUInt64 () {
    var i = bufferutils.readUInt64LE(buffer, offset)
    offset += 8
    return i
  }

  function readVarInt () {
    var vi = bufferutils.readVarInt(buffer, offset)
    offset += vi.size
    return vi.number
  }

  function readScript () {
    return readSlice(readVarInt())
  }

  function readJSDescription () {
    var jsdesc = JSDescription.fromBuffer(buffer.slice(offset), true)
    offset += jsdesc.byteLength()
    return jsdesc
  }

  var tx = new Transaction()
  tx.version = readUInt32()

  var vinLen = readVarInt()
  for (var i = 0; i < vinLen; ++i) {
    tx.ins.push({
      hash: readSlice(32),
      index: readUInt32(),
      script: readScript(),
      sequence: readUInt32()
    })
  }

  var voutLen = readVarInt()
  for (i = 0; i < voutLen; ++i) {
    tx.outs.push({
      value: readUInt64(),
      script: readScript()
    })
  }

  tx.locktime = readUInt32()

  if (tx.version >= 2) {
    var vjoinsplitLen = readVarInt()
    for (i = 0; i < vjoinsplitLen; ++i) {
      var jsdesc = readJSDescription()
      tx.jss.push(jsdesc)
    }
    if (vjoinsplitLen > 0) {
      tx.joinSplitPubKey = readSlice(32)
      tx.joinSplitSig = readSlice(64)
    }
  }

  if (__noStrict) return tx
  if (offset !== buffer.length) throw new Error('Transaction has unexpected data')

  return tx
}

Transaction.fromHex = function (hex) {
  return Transaction.fromBuffer(new Buffer(hex, 'hex'))
}

Transaction.isCoinbaseHash = function (buffer) {
  return Array.prototype.every.call(buffer, function (x) {
    return x === 0
  })
}

var EMPTY_SCRIPT = new Buffer(0)

Transaction.prototype.addInput = function (hash, index, sequence, scriptSig) {
  typeforce(types.tuple(
    types.Hash256bit,
    types.UInt32,
    types.maybe(types.UInt32),
    types.maybe(types.Buffer)
  ), arguments)

  if (types.Null(sequence)) {
    sequence = Transaction.DEFAULT_SEQUENCE
  }

  // Add the input and return the input's index
  return (this.ins.push({
    hash: hash,
    index: index,
    script: scriptSig || EMPTY_SCRIPT,
    sequence: sequence
  }) - 1)
}

Transaction.prototype.addOutput = function (scriptPubKey, value) {
  typeforce(types.tuple(types.Buffer, types.UInt53), arguments)

  // Add the output and return the output's index
  return (this.outs.push({
    script: scriptPubKey,
    value: value
  }) - 1)
}

Transaction.prototype.addShieldedOutput = function (addr, value, memo) {
  typeforce(types.tuple(
    types.PaymentAddress,
    types.UInt53,
    types.maybe(types.Buffer)
  ), arguments)

  // Add the JSOutput and return the JSOutput's index
  return (this._jsouts.push(new JSOutput(addr, value, memo)) - 1)
}

Transaction.prototype.setAnchor = function (anchor) {
  typeforce(types.Hash256bit, anchor)

  this._anchor = anchor
}

Transaction.prototype.getProofs = function (provingServiceUri, callbackfn) {
  if (!this._anchor) throw new Error('Must call setAnchor() before getProofs()')

  var keyPair = sodium.crypto_sign_keypair()
  this.joinSplitPubKey = new Buffer(keyPair.publicKey)

  for (var i = 0; i < this._jsouts.length; i += 2) {
    var inputs = [
      JSInput.dummy(),
      JSInput.dummy()
    ]

    var outputs = [
      this._jsouts[i],
      this._jsouts[i + 1] || JSOutput.dummy()
    ]

    var value = outputs.reduce(function (sum, output) { return sum + output.value }, 0)
    this.jss.push(JSDescription.withWitness(inputs, outputs, this.joinSplitPubKey, value, 0, this._anchor))
  }

  var request = new Buffer(
    bufferutils.varIntSize(this.jss.length) +
    this.jss.reduce(function (sum, jsdesc) { return sum + jsdesc.witness.byteLength() }, 0)
  )
  var offset = 0
  function writeSlice (slice) {
    slice.copy(request, offset)
    offset += slice.length
  }

  function writeVarInt (i) {
    var n = bufferutils.writeVarInt(request, i, offset)
    offset += n
  }

  writeVarInt(this.jss.length)
  this.jss.forEach(function (jsdesc) {
    writeSlice(jsdesc.witness.toBuffer())
  })

  var sock = zmq.socket('req')
  sock.connect(provingServiceUri)
  sock.send(request)

  sock.on('message', function (msg) {
    var offset = 0
    function readVarInt () {
      var vi = bufferutils.readVarInt(msg, offset)
      offset += vi.size
      return vi.number
    }

    function readZCProof () {
      var proof = ZCProof.fromBuffer(msg.slice(offset), true)
      offset += proof.byteLength()
      return proof
    }

    var proofsLen = readVarInt()
    for (var i = 0; i < proofsLen; ++i) {
      this.jss[i].proof = readZCProof()
    }

    sock.close()
    callbackfn()
  }.bind(this))
}

Transaction.prototype.byteLength = function () {
  function scriptSize (someScript) {
    var length = someScript.length

    return bufferutils.varIntSize(length) + length
  }

  var jsLen = 0
  if (this.version >= 2) {
    jsLen = (
      bufferutils.varIntSize(this.jss.length) +
      this.jss.reduce(function (sum, jsdesc) { return sum + jsdesc.byteLength() }, 0) +
      (this.jss.length > 0 ? 12 : 0)
    )
  }

  return (
    8 +
    jsLen +
    bufferutils.varIntSize(this.ins.length) +
    bufferutils.varIntSize(this.outs.length) +
    this.ins.reduce(function (sum, input) { return sum + 40 + scriptSize(input.script) }, 0) +
    this.outs.reduce(function (sum, output) { return sum + 8 + scriptSize(output.script) }, 0)
  )
}

Transaction.prototype.clone = function () {
  var newTx = new Transaction()
  newTx.version = this.version
  newTx.locktime = this.locktime

  newTx.ins = this.ins.map(function (txIn) {
    return {
      hash: txIn.hash,
      index: txIn.index,
      script: txIn.script,
      sequence: txIn.sequence
    }
  })

  newTx.outs = this.outs.map(function (txOut) {
    return {
      script: txOut.script,
      value: txOut.value
    }
  })

  if (this.version >= 2) {
    newTx.jss = this.jss.map(function (jsdesc) {
      return jsdesc.clone()
    })
    if (this.jss.length > 0) {
      newTx.joinSplitPubKey = this.joinSplitPubKey
      newTx.joinSplitSig = this.joinSplitSig
    }
  }

  return newTx
}

var ONE = new Buffer('0000000000000000000000000000000000000000000000000000000000000001', 'hex')
var VALUE_UINT64_MAX = new Buffer('ffffffffffffffff', 'hex')

/**
 * Hash transaction for signing a specific input.
 *
 * Bitcoin uses a different hash for each signed transaction input.
 * This method copies the transaction, makes the necessary changes based on the
 * hashType, and then hashes the result.
 * This hash can then be used to sign the provided transaction input.
 */
Transaction.prototype.hashForSignature = function (inIndex, prevOutScript, hashType) {
  typeforce(types.tuple(types.UInt32, types.Buffer, /* types.UInt8 */ types.Number), arguments)

  // https://github.com/bitcoin/bitcoin/blob/master/src/test/sighash_tests.cpp#L29
  if (inIndex >= this.ins.length) return ONE

  var txTmp = this.clone()

  // in case concatenating two scripts ends up with two codeseparators,
  // or an extra one at the end, this prevents all those possible incompatibilities.
  var hashScript = bscript.compile(bscript.decompile(prevOutScript).filter(function (x) {
    return x !== opcodes.OP_CODESEPARATOR
  }))
  var i

  // blank out other inputs' signatures
  txTmp.ins.forEach(function (input) { input.script = EMPTY_SCRIPT })
  txTmp.ins[inIndex].script = hashScript

  // blank out some of the inputs
  if ((hashType & 0x1f) === Transaction.SIGHASH_NONE) {
    // wildcard payee
    txTmp.outs = []

    // let the others update at will
    txTmp.ins.forEach(function (input, i) {
      if (i !== inIndex) {
        input.sequence = 0
      }
    })
  } else if ((hashType & 0x1f) === Transaction.SIGHASH_SINGLE) {
    var nOut = inIndex

    // only lock-in the txOut payee at same index as txIn
    // https://github.com/bitcoin/bitcoin/blob/master/src/test/sighash_tests.cpp#L60
    if (nOut >= this.outs.length) return ONE

    txTmp.outs = txTmp.outs.slice(0, nOut + 1)

    // blank all other outputs (clear scriptPubKey, value === -1)
    var stubOut = {
      script: EMPTY_SCRIPT,
      valueBuffer: VALUE_UINT64_MAX
    }

    for (i = 0; i < nOut; i++) {
      txTmp.outs[i] = stubOut
    }

    // let the others update at will
    txTmp.ins.forEach(function (input, i) {
      if (i !== inIndex) {
        input.sequence = 0
      }
    })
  }

  // blank out other inputs completely, not recommended for open transactions
  if (hashType & Transaction.SIGHASH_ANYONECANPAY) {
    txTmp.ins[0] = txTmp.ins[inIndex]
    txTmp.ins = txTmp.ins.slice(0, 1)
  }

  // serialize and hash
  var buffer = new Buffer(txTmp.byteLength() + 4)
  buffer.writeInt32LE(hashType, buffer.length - 4)
  txTmp.toBuffer().copy(buffer, 0)

  return bcrypto.hash256(buffer)
}

Transaction.prototype.getHash = function () {
  return bcrypto.hash256(this.toBuffer())
}

Transaction.prototype.getId = function () {
  // transaction hash's are displayed in reverse order
  return [].reverse.call(this.getHash()).toString('hex')
}

Transaction.prototype.toBuffer = function () {
  var buffer = new Buffer(this.byteLength())

  var offset = 0
  function writeSlice (slice) {
    slice.copy(buffer, offset)
    offset += slice.length
  }

  function writeUInt32 (i) {
    buffer.writeUInt32LE(i, offset)
    offset += 4
  }

  function writeUInt64 (i) {
    bufferutils.writeUInt64LE(buffer, i, offset)
    offset += 8
  }

  function writeVarInt (i) {
    var n = bufferutils.writeVarInt(buffer, i, offset)
    offset += n
  }

  writeUInt32(this.version)
  writeVarInt(this.ins.length)

  this.ins.forEach(function (txIn) {
    writeSlice(txIn.hash)
    writeUInt32(txIn.index)
    writeVarInt(txIn.script.length)
    writeSlice(txIn.script)
    writeUInt32(txIn.sequence)
  })

  writeVarInt(this.outs.length)
  this.outs.forEach(function (txOut) {
    if (!txOut.valueBuffer) {
      writeUInt64(txOut.value)
    } else {
      writeSlice(txOut.valueBuffer)
    }

    writeVarInt(txOut.script.length)
    writeSlice(txOut.script)
  })

  writeUInt32(this.locktime)

  if (this.version >= 2) {
    writeVarInt(this.jss.length)
    this.jss.forEach(function (jsdesc) {
      writeSlice(jsdesc.toBuffer())
    })
    if (this.jss.length > 0) {
      writeSlice(this.joinSplitPubKey)
      writeSlice(this.joinSplitSig)
    }
  }

  return buffer
}

Transaction.prototype.toHex = function () {
  return this.toBuffer().toString('hex')
}

Transaction.prototype.setInputScript = function (index, scriptSig) {
  typeforce(types.tuple(types.Number, types.Buffer), arguments)

  this.ins[index].script = scriptSig
}

module.exports = Transaction
