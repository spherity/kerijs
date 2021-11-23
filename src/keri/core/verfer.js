const libsodium = require('libsodium-wrappers-sumo');
const { Matter } = require('./matter');
const codeAndLength = require('./derivationCode&Length');

/**
 * @description   Verfer is Matter subclass with method to verify signature of serialization
    using the .raw as verifier key and .code for signature cipher suite.

    See Matter for inherited attributes and properties:

    Attributes:

    Properties:

    Methods:
        verify: verifies signature
 */
class Verfer extends Matter {
  // eslint-disable-next-line max-len
  constructor(raw = null,code = codeAndLength.oneCharCode.Ed25519N, qb64b=null, qb64 = null, qb2 = null) {
      console.log("Value of Code Inside Verfer is ,code",code)
      super(raw, code, qb64b, qb64, qb2);
    if (Object.values(codeAndLength.oneCharCode.Ed25519N).includes(this.getCode)
            || Object.values(codeAndLength.oneCharCode.Ed25519).includes(this.getCode)) {
      this.verifySig = this.ed25519;
    } else {
      throw new Error(`Unsupported code = ${this.getCode} for verifier.`);
    }
  }

  /**
     *
     * @param {bytes} sig   bytes signature
     * @param {bytes} ser   bytes serialization
     */
  verify(sig, ser) {
    return this.verifySig(sig, ser, this.raw());
  }

  /**
     * @description This method will verify ed25519 signature on Serialization using  public key
     * @param {bytes} sig
     * @param {bytes} ser
     * @param {bytes} key
     */

  // eslint-disable-next-line class-methods-use-this
  ed25519(sig, ser, key) {
    try {
      const result = libsodium.crypto_sign_verify_detached(sig, ser, key);
      if (result) {
        return true;
      }
      return false;
    } catch (error) {
      throw new Error(error);
    }
  }
}

module.exports = { Verfer };
