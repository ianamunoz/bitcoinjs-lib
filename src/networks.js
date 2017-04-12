// https://en.bitcoin.it/wiki/List_of_address_prefixes
// Dogecoin BIP32 is a proposed standard: https://bitcointalk.org/index.php?topic=409731

module.exports = {
  zcash: {
    messagePrefix: '\x18Zcash Signed Message:\n',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x1cb8,
    scriptHash: 0x1cbd,
    wif: 0x80,
    zcPaymentAddress: 0x169a,
    zcSpendingKey: 0xab36,
    dustThreshold: 54 // https://github.com/bitcoin/bitcoin/blob/v0.9.2/src/core.h#L151-L162
  },
  testnet: {
    messagePrefix: '\x18Zcash Signed Message:\n',
    bip32: {
      public: 0x043587cf,
      private: 0x04358394
    },
    pubKeyHash: 0x1d25,
    scriptHash: 0x1cba,
    wif: 0xef,
    zcPaymentAddress: 0x16b6,
    zcSpendingKey: 0xac08,
    dustThreshold: 54
  }
}
