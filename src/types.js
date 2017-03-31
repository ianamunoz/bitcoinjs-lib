var typeforce = require('typeforce')

function nBuffer (value, n) {
  typeforce(types.Buffer, value)
  if (value.length !== n) throw new typeforce.TfTypeError('Expected ' + (n * 8) + '-bit Buffer, got ' + (value.length * 8) + '-bit Buffer')

  return true
}

function Hash160bit (value) { return nBuffer(value, 20) }
function Hash256bit (value) { return nBuffer(value, 32) }
function Buffer256bit (value) { return nBuffer(value, 32) }

function Buffer252bit (value) {
  return Buffer256bit(value) && (value[0] & 0x0f) === value[0]
}

var UINT53_MAX = Math.pow(2, 53) - 1
function UInt2 (value) { return (value & 3) === value }
function UInt8 (value) { return (value & 0xff) === value }
function UInt32 (value) { return (value >>> 0) === value }
function UInt53 (value) {
  return typeforce.Number(value) &&
    value >= 0 &&
    value <= UINT53_MAX &&
    Math.floor(value) === value
}

function BoolNum (value) {
  return typeforce.Number(value) &&
    value >= 0 &&
    value <= 1
}

// external dependent types
var BigInt = typeforce.quacksLike('BigInteger')
var ECPoint = typeforce.quacksLike('Point')

// exposed, external Zcash API
var PaymentAddress = typeforce.compile({
  a_pk: Buffer256bit,
  pk_enc: Buffer256bit
})
var SpendingKey = typeforce.compile({
  a_sk: Buffer252bit
})
var Note = typeforce.compile({
  a_pk: Buffer256bit,
  value: UInt53,
  rho: Buffer256bit,
  r: Buffer256bit
})
var ZCIncrementalMerkleTree = typeforce.compile({
  left: typeforce.maybe(Hash256bit),
  right: typeforce.maybe(Hash256bit),
  parents: [typeforce.maybe(Hash256bit)]
})
var ZCIncrementalWitness = typeforce.compile({
  tree: ZCIncrementalMerkleTree,
  filled: [Hash256bit],
  cursor: typeforce.maybe(ZCIncrementalMerkleTree)
})
var JSInput = typeforce.compile({
  witness: ZCIncrementalWitness,
  note: Note,
  key: SpendingKey
})
var JSOutput = typeforce.compile({
  addr: PaymentAddress,
  value: UInt53,
  memo: typeforce.Buffer
})

// exposed, external API
var ECSignature = typeforce.compile({ r: BigInt, s: BigInt })
var Network = typeforce.compile({
  messagePrefix: typeforce.oneOf(typeforce.Buffer, typeforce.String),
  bip32: {
    public: UInt32,
    private: UInt32
  },
  pubKeyHash: UInt8,
  scriptHash: UInt8,
  wif: UInt8,
  dustThreshold: UInt53
})

// extend typeforce types with ours
var types = {
  BigInt: BigInt,
  BoolNum: BoolNum,
  Buffer252bit: Buffer252bit,
  Buffer256bit: Buffer256bit,
  ECPoint: ECPoint,
  ECSignature: ECSignature,
  Hash160bit: Hash160bit,
  Hash256bit: Hash256bit,
  JSInput: JSInput,
  JSOutput: JSOutput,
  Network: Network,
  Note: Note,
  PaymentAddress: PaymentAddress,
  SpendingKey: SpendingKey,
  UInt2: UInt2,
  UInt8: UInt8,
  UInt32: UInt32,
  UInt53: UInt53,
  ZCIncrementalWitness: ZCIncrementalWitness
}

for (var typeName in typeforce) {
  types[typeName] = typeforce[typeName]
}

module.exports = types
