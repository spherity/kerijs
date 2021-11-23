const libsodium = require('libsodium-wrappers-sumo');
const { Matter } = require('./matter');
const derivationCodes = require('./derivationCode&Length');
const { Verfer } = require('./verfer');
const { Cigar } = require('./Cigar');
const { Siger } = require('./siger');
const { range } = require('./utls');

/**
 * @description   Signer is Matter subclass with method to create signature of serialization
    using the .raw as signing (private) key seed, .code as cipher suite for
    signing and new property .verfer whose property .raw is public key for signing.
    If not provided .verfer is generated from private key seed using .code
    as cipher suite for creating key-pair.


    See Matter for inherited attributes and properties:
 */

class Signer extends Matter {

  /**
   * @description Assign signing cipher suite function to ._sign
   * @param {*} raw bytes crypto material seed or private key
   * @param {*} code  code is derivation code
   * @param {*} transferable transferable is Boolean True means verifier code is transferable
                                    False othersize non-transerable
   * @param {*} lib 
   * @param {*} qb64 
   */
  constructor(
    raw = null,
    code = derivationCodes.oneCharCode.Ed25519_Seed,
    transferable = true,
    lib = null,
    qb64 = null,
  ) {
    let setVerfer;
    let seedKeypair;
    try {
      super(raw,code,null, qb64);
    } catch (error) {
      console.log("Empty material error : ")
      if (code === derivationCodes.oneCharCode.Ed25519_Seed) {
        raw = libsodium.randombytes_buf(libsodium.crypto_sign_SEEDBYTES);
        raw = Buffer.from(raw, 'binary');
        console.log("Value of Raw buffer is = ",raw.toString('hex'))
        super(raw, code, null, null);
      } else {
        throw new Error(`Unsupported signer code = ${code}.`);
      }
    }
    if (code === derivationCodes.oneCharCode.Ed25519_Seed) {
      this.getSign = this.ed25519;
      console.log("Value of this.getRaw = ",this.getRaw)
      if (raw == null) {
        raw = this.getRaw;
      }
      seedKeypair = libsodium.crypto_sign_seed_keypair(raw);
      const verkey = Buffer.from(seedKeypair.publicKey, 'binary');

      const sigkey = Buffer.from(seedKeypair.privateKey, 'binary');
      if (transferable) {
        setVerfer = new Verfer(
          verkey,
          derivationCodes.oneCharCode.Ed25519,
        );
      } else {
        setVerfer = new Verfer(
          verkey,
          derivationCodes.oneCharCode.Ed25519N,
        );
      }
    } else {
      throw new Error(
        `Unsupported signer code = ${derivationCodes.oneCharCode.Ed25519N}.`,
      );
    }
    this.getVerfer = setVerfer;
  }

  static async initLibsodium() {
    await libsodium.ready;
  }

  /**
 * @description Property verfer:
        Returns Verfer instance
        Assumes ._verfer is correctly assigned
 */
  verfer() {
    return this.getVerfer;
  }

  /**
 * @description Returns either Sigver or Siger (indexed) instance of cryptographic
        signature material on bytes serialization ser

         If index is None
            return Sigver instance
        Else
            return Siger instance

             ser is bytes serialization
            index is int index of associated verifier key in event keys
 * @param {*} ser
 * @param {*} index
 */
  sign(ser, index = null) {
    console.log("Value of his.verfer()",this.verfer())
    return this.getSign(ser, this.raw(), this.verfer(), index);
  }

  /**
   * @description Returns signature
   * @param {*} ser ser is bytes serialization
   * @param {*} seed seed is bytes seed (private key)
   * @param {*} verfer verfer is Verfer instance. verfer.raw is public key
   * @param {*} index index is index of offset into signers list or None
   */
  // eslint-disable-next-line class-methods-use-this
  ed25519(ser, seed, verfer, index) {
    let sig = libsodium.crypto_sign_detached(
      ser,
      Buffer.concat([seed, verfer.raw()]),
    );
    sig = Buffer.from(sig, 'binary');
    if (index == null) {
      console.log("Value of Sig = ",sig , derivationCodes.twoCharCode.Ed25519_SIG)
      let kwa = [sig, derivationCodes.twoCharCode.Ed25519_SIG, verfer]
      const response = new Cigar(null, ...kwa);
      response.setVerfer(verfer);
      return response;
    }else{
      const args = [sig, null, null, derivationCodes.SigTwoCodex.Ed25519];
    return new Siger(verfer, ...args);
    }
   
  }
}

/**
     * @description Returns list of Signers for Ed25519
     * @param {*} root          root is bytes 16 byte long root key (salt/seed) from
     *                          which seeds for Signers
                                in list are derived
                                 random root created if not provided
     * @param {*} count          count is number of signers in list
     * @param {*} transferable transferable is boolean true means signer.verfer code is transferable
                                non-transferable otherwise
     */
async function generateSigners(root = null, count = 8) {
  await libsodium.ready;
  if (!root) {
    root = libsodium.randombytes_buf(libsodium.crypto_pwhash_SALTBYTES);
  }
  const signers = [];
  let [path, seed] = null;
  for (const i in range(count)) {
    path = i.toString(16);
    seed = libsodium.crypto_pwhash(
      32,
      path,
      root,
      libsodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      libsodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      (alg = libsodium.crypto_pwhash_ALG_DEFAULT),
    );
    signers.push(new Signer(seed));
  }
  return signers;
}

/**
     * @description  Returns list of fully qualified Base64 secret seeds for Ed25519 private keys
     * @param {*} root root is bytes 16 byte long root key (salt/seed) from which seeds for Signers
            in list are derived
            random root created if not provided
     * @param {*} count count is number of signers in list
     */
function generateSecrets(root = null, count = 8) {
  const signrs = [];
  const signers = generateSigners(root, count);

  for (const signer in signers) {
    signrs.push[signer.qb64()];
  }

  return signrs;
}

module.exports = { Signer, generateSigners, generateSecrets };
