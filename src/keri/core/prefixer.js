/* eslint-disable class-methods-use-this */
/* eslint-disable no-underscore-dangle */
const blake3 = require('blake3');
const libsodium = require('libsodium-wrappers-sumo');
const {Matter } = require('./matter');
const {Serder } = require('./serder');
const { extractValues } = require('./utls');
const derivationCodes = require('./derivationCode&Length');
const { Ilks, IcpLabels, DipLabels, IcpExcludes, DipExcludes } = require('./core');
const { Signer, Cigar, Sigver, Verfer } = require('./index');


/**
 * @description  Prefixer is Matter subclass for autonomic identifier prefix using
    derivation as determined by code from ked

    Attributes:

    Inherited Properties:  (see Matter)
        .pad  is int number of pad chars given raw
        .code is  str derivation code to indicate cypher suite
        .raw is bytes crypto material only without code
        .index is int count of attached crypto material by context (receipts)
        .qb64 is str in Base64 fully qualified with derivation code + crypto mat
        .qb64b is bytes in Base64 fully qualified with derivation code + crypto mat
        .qb2  is bytes in binary with derivation code + crypto material
        .nontrans is Boolean, True when non-transferable derivation code False otherwise

    Properties:

    Methods:
        verify():  Verifies derivation of aid prefix from a ked

    Hidden:
        ._pad is method to compute  .pad property
        ._code is str value for .code property
        ._raw is bytes value for .raw property
        ._index is int value for .index property
        ._infil is method to compute fully qualified Base64 from .raw and .code
        ._exfil is method to extract .code and .raw from fully qualified Base64
 */

class Prefixer extends Matter {
  //        elements in digest or signature derivation from inception icp
  //  IcpLabels ["sith", "keys", "nxt", "toad", "wits", "cnfg"]

  //  elements in digest or signature derivation from delegated inception dip
  //  DipLabels  ["sith", "keys", "nxt", "toad", "wits", "perm", "seal"]


  Dummy = "#"  // dummy spaceholder char for pre. Must not be a valid Base64 char
  //# element labels to exclude in digest or signature derivation from inception icp
  IcpExcludes = ["i"]
  //# element labels to exclude in digest or signature derivation from delegated inception dip
  DipExcludes = ["i"]

  /**
   * @description  // This constructor will assign
   *  ._verify to verify derivation of aid  = .qb64
   */
  constructor(

    // """
    // assign ._derive to derive derivatin of aid prefix from ked
    // assign ._verify to verify derivation of aid prefix  from ked

    // Default code is None to force EmptyMaterialError when only raw provided but
    // not code.

    // Inherited Parameters:
    //     raw is bytes of unqualified crypto material usable for crypto operations
    //     qb64b is bytes of fully qualified crypto material
    //     qb64 is str or bytes  of fully qualified crypto material
    //     qb2 is bytes of fully qualified crypto material
    //     code is str of derivation code
    //     index is int of count of attached receipts for CryCntDex codes

    // Parameters:
    //     seed is bytes seed when signature derivation
    //     secret is qb64 when signature derivation when applicable
    //        one of seed or secret must be provided when signature derivation

    // """
    raw = null,
    code = derivationCodes.oneCharCode.Ed25519N,
    ked = null,
    seed = null,
    secret = null,
    qb64 = null,
    qb2 = null,
  ) {
    let deriveFunc = null;

    try {
      super(raw, code, qb64, qb2);
    } catch (error) {
      console.log("INSIDE CATCH ===========================>",(!(ked || (ked.c && ked.i))));
      if (!(ked || (ked.c && ked.i))) throw error; // throw error if no ked found
      if(!code){
        super(null,code, null, ked.i)
        code = this.code();
      }


      

      if (code === derivationCodes.oneCharCode.Ed25519N) {
        deriveFunc = DeriveBasicEd25519N;
      } else if (code === derivationCodes.oneCharCode.Ed25519) {
        deriveFunc = DeriveBasicEd25519;
      } else if (code === derivationCodes.oneCharCode.Blake3_256) {
        deriveFunc = DeriveDigBlake3_256;
      } else if (code === derivationCodes.twoCharCode.Ed25519) {
        deriveFunc = DeriveSigEd25519;
      } else throw new Error(`Unsupported code = ${code} for prefixer.`);

      const verfer = deriveFunc(ked, seed, secret); // else obtain AID using ked
      super(verfer.raw, verfer.code);
    }

    if (this.getCode === derivationCodes.oneCharCode.Ed25519N) {
      this.verifyDerivation = this.VerifyBasicEd25519N;
    } else if (this.getCode === derivationCodes.oneCharCode.Ed25519) {
      this.verifyDerivation = this.VerifyBasicEd25519;
    } else if (this.getCode === derivationCodes.oneCharCode.Blake3_256) {
      this.verifyDerivation = this.verifyDigBlake3_256;
    } else if (this.getCode === derivationCodes.twoCharCode.Ed25519) {
      this.verifyDerivation = this.VerifySigEd25519;
    } else throw new Error(`Unsupported code = ${this.code()} for prefixer.`);
  }

  static async initLibsodium() {
    await libsodium.ready;
  }

  /**
   * @description   Returns tuple (raw, code) of basic nontransferable
   * Ed25519 prefix (qb64) as derived from key event dict ke
   * @param {*} ked  ked is inception key event dict
   * @param {*} seed seed is only used for sig derivation it is the secret key/secret
   * @param {*} secret secret or private key
   */
  derive(ked, seed = null, secret = null) {
    return this.derive(ked, seed, secret);
  }

  /**
   * @description  This function will return TRUE   if derivation from ked for .code matches .qb64 and
                If prefixed also verifies ked["i"] matches .qb64
                False otherwise

   * @param {*} ked inception key event dict
   */
  verify(ked,prefixed=false) {
   // Object.values(Ilks.icp).includes(labels[l])
    if(!(ked["t"] == Ilks.icp || Ilks.dip)){
      throw new Error(`Nonincepting ilk= ${ked["t"]} for prefix derivation."`)
    }
    return this.verifyDerivation(ked, this.qb64(), prefixed);
  }

  /**
     * @description This will return  True if verified raises exception otherwise
            Verify derivation of fully qualified Base64 pre from inception iked dict
     * @param {*} ked    ked is inception key event dict
     * @param {*} pre   pre is Base64 fully qualified prefix
     */
  // eslint-disable-next-line class-methods-use-this
  VerifyBasicEd25519N(ked, pre, prefixed=false) {
    let keys = null;

    try {
      keys = ked.k;
      if (keys.length !== 1) {
        console.log("KEY LENGTH ==",keys.length)
        return false;
      }
      if (keys[0] !== pre) {console.log('key[0]  is not equal to pre'); return false; }
      if(prefixed && ked.i != pre){
        
        console.log('prefixed && ked["i"]=================> FALSE',pre , prefixed , ked.i)
        return false
      }
      if (ked.n) {
        console.log('ked.n =========================> FALSE')
        return false; }
    } catch (e) {
      console.log('e =========================> FALSE')
      return false;
    }
    return true;
  }

  /**
     * @description  Returns True if verified raises exception otherwise
                     Verify derivation of fully qualified Base64 prefix from
                     inception key event dict (ked)
     * @param {*} ked    ked is inception key event dict
     * @param {*} pre   pre is Base64 fully qualified prefix
     */
  // eslint-disable-next-line class-methods-use-this
  VerifyBasicEd25519(ked, pre,prefixed=false) {
    const  keys  = ked.k;
    try {
      if (keys.length != 1) {

        console.log("Failed here ",keys)
        return false;
      }
      if (prefixed && ked.i != pre) {
        console.log("INSIDE HEREE : ===================>")
        return false;
      }
    } catch (e) {
      console.log("Inside catch is =================?",e)
      return false;
    }
    return true;
  }

  /**
     * @description : Verify derivation of fully qualified Base64 prefix from
                      inception key event dict (ked). returns TRUE if verified else raise exception
             * @param {*} ked    ked is inception key event dict
             * @param {*} pre   pre is Base64 fully qualified prefix
     */
  // eslint-disable-next-line camelcase
  verifyDigBlake3_256(ked, pre, prefixed=false) {
    let [raw, code, response, crymat] = '';
    try {
      response = DeriveDigBlake3_256(ked);
      raw = response.raw;
      code = response.code;

      crymat = new Crymat(raw, null, null, code);
      if ((prefixed && crymat.qb64()) !== pre) return false;
    } catch (error) {
      return false;
    }
    return true;
  }

  /**
* @description : Verify derivation of fully qualified Base64 prefix from
    inception key event dict (ked). returns TRUE if verified else raise exception
     * @param {*} ked    ked is inception key event dict
     * @param {*} pre   pre is Base64 fully qualified prefix
     */
  // eslint-disable-next-line no-underscore-dangle
  // eslint-disable-next-line class-methods-use-this
  VerifySigEd25519(ked, pre, prefixed=false) {
    let ilk = null;
    let labels;
    let values;
    let ser;
    const keys = ked.keys;
    let verfer;
    let sigver = null;
    let dked = ked
    try {
      ilk = dked.t;
      if (ilk === Ilks.icp) {
        for(let key in dked){
          if(!(dked(key) in this.IcpExcludes )){
            labels = [dked(key)]
          }
        }
        
       // labels = IcpLabels;
      }
      if (ilk === Ilks.dip){
        for(let key in dked){
          if(!(dked(key) in this.DipExcludes )){
            labels = [dked(key)]
          }
        }
      }
      //labels = DipLabels;
      else throw new Error(`Invalid ilk = ${ilk} to derive pre.`);


      dked["i"] = `${this.Dummy*derivationCodes.Codes[derivationCodes.oneCharCode.Ed25519_Sig].fs}`
      //"{}".format(self.Dummy*Matter.Codes[MtrDex.Ed25519_Sig].fs)
           let serder =  new Serder(null, dked);
            dked = serder.ked();    //# use updated ked with valid vs element
      for (const l in labels) {
        if (!Object.values(dked).includes(l)) {
          throw new Error(`Missing element = ${l} from ked.`);
        }
      }

    

      // values = extractValues(ked, labels);
      // ser = Buffer.from(''.concat(values), 'utf-8');
      try {
       let keys = dked["k"]
        if (keys.length !== 1) throw new Error(`Basic derivation needs at most 1 key got ${keys.length} keys instead`);
        verfer = new Verfer(null, keys[0]);
      } catch (e) {
        throw new Error(`Error extracting public key = ${e}`);
      }
      if (
        !Object.values(derivationCodes.oneCharCode.Ed25519).includes(
          verfer.code(),
        )
      ) {
        throw new Error(`Invalid derivation code = ${verfer.code()}`);
      }
      if((prefixed && ked["i"]) != pre){
        return  false
      }
      let kwa = [null, derivationCodes.allCharcodes.Ed25519N, null, pre]
      let cigar = new  Cigar(verfer, ...kwa)

     let response = cigar.verfer.verify(sig=cigar.raw, ser=serder.raw)
      // sigver = new Sigver(
      //   null,
      //   derivationCodes.twoCharCode.Ed25519,
      //   verfer,
      //   0,
      //   pre,
      // );
      const result = sigver.verfer().verify(sigver.raw(), ser);
      return result;
    } catch (exception) {
      return false;
    }
  }
}

/**
 * @description  Returns tuple raw, code of basic Ed25519 prefix (qb64)
                 as derived from key event dict ked
 * @param {*} ked
 * @param {*} seed
 * @param {*} secret
 */
function DeriveBasicEd25519(
  ked,
  seed = null,
  secret = null,
  code = derivationCodes.oneCharCode.Ed25519,
) {
  let verfer = null;
  let keys;
  try {
    keys = ked.keys;
    if (keys.length !== 1) throw new Error(`Basic derivation needs at most 1 key got ${keys.length} keys instead`);

    verfer = new Verfer(null, keys[0]);
  } catch (e) {
    throw new Error(`Error extracting public key = ${e}`);
  }

  if (
    !Object.values(derivationCodes.oneCharCode.Ed25519).includes(verfer.code())
  ) {
    throw new Error(`Invalid derivation code = ${verfer.code()}.`);
  }

  return { raw: verfer.raw(), code: verfer.code() };
}

/**
 * @descriptionReturns return  (raw, code) of basic nontransferable Ed25519 prefix (qb64)
 * @param {*} ked  ked is inception key event dict
 * @param {*} seed seed is only used for sig derivation it is the secret key/secret
 * @param {*} secret secret or private key
 */

function DeriveBasicEd25519N(ked) {
  let verfer = null;
  let keys;
  try {
    keys = ked.k;
    if (keys.length !== 1) throw new Error(`Basic derivation needs at most 1 key got ${keys.length} keys instead`);
    verfer = new Verfer(null, derivationCodes.oneCharCode.Ed25519N, null, keys[0]);
  } catch (e) {
    throw new Error(`Error extracting public key = ${e}`);
  }

  if (
    !Object.values(derivationCodes.oneCharCode.Ed25519N).includes(
      verfer.code(),
    )
  ) {
    throw new Error(`Invalid derivation code = ${verfer.code()}.`);
  }

  try {
    if (
      Object.values(derivationCodes.oneCharCode.Ed25519N).includes(
        verfer.code(),
      )
      && ked.nxt
    ) {
      throw new Error(`Non-empty nxt = ${
        ked.nxt
      } for non-transferable code = ${verfer.code()}`);
    }
  } catch (e) {
    throw new Error(`Error checking nxt = ${e}`);
  }

  return { raw: verfer.raw(), code: verfer.code() };
}

/**
* @description Returns raw, code of basic Ed25519 pre (qb64)
             as derived from key event dict ked
* @param {*} ked  ked is inception key event dict
* @param {*} seed seed is only used for sig derivation it is the secret key/secret
* @param {*} secret secret or private key
*/
function DeriveDigBlake3_256(ked) {
  let labels = [];
  let objKeys = [];
  let values = null;
  let ser = null;
  let dig = null;
  const { t } = ked;

  if (t === Ilks.icp) {
    objKeys = Object.keys(ked);
    for(let keys in objKeys){
      if(!(IcpExcludes.includes(objKeys[keys]))){
        labels.push(objKeys[keys]);
      }
    }
    // labels = IcpLabels;
  } 
  // if (ilk === Ilks.icp) labels = IcpLabels;
  else if (t === Ilks.dip) labels = DipLabels;
  else throw new Error(`Invalid ilk = ${t} to derive pre.`);

  ked.pre = 'a'.repeat(
    derivationCodes.CryOneSizes[derivationCodes.oneCharCode.Blake3_256],
  );
   let serder = new Serder(null, ked, null);
  // serder.set_raw(serder.getRaw);
  ked = serder.ked();
  serder.set_ked(ked);
  // serder.set_kind()
//  serder.set_raw(serder.getRaw);
  // # put in dummy pre to get size correct
  for (let l in labels) {
    if (Object.values(ked).includes(labels[l])) {
      throw new Error(`Missing element = ${l} from ked.`);
    }
  }

  values = extractValues(ked, labels);
  ser = Buffer.from(''.concat(values), 'utf-8');
  const hasher = blake3.createHash();
  dig = hasher.update(ser).digest({length: 64 });

  return { raw: dig, code: derivationCodes.oneCharCode.Blake3_256 };
}

/**
 * @description   Returns  raw, code of basic Ed25519 pre (qb64)
            as derived from key event dict ked
 * @param {*} ked  ked is inception key event dict
 * @param {*} seed seed is only used for sig derivation it is the secret key/secret
 * @param {*} secret secret or private key
 *
 *
 */
function DeriveSigEd25519(ked, seed = null, secret = null) {
  let labels = null;
  let values = null;
  let ser = null;
  let keys = null;
  let verfer = null;
  let signer = null;
  let sigver = null;
  const { ilk } = ked;
  if (ilk === Ilks.icp) {
    labels = IcpLabels;
  } else if (ilk === Ilks.dip) {
    labels = DipLabels;
  } else throw new Error(`Invalid ilk = ${ilk} to derive pre.`);

  for (let l in labels) {
    if (!Object.values(ked).includes(labels[l])) {
      throw new Error(`Missing element = ${l} from ked.`);
    }
  }
  values = extractValues(ked, labels);
  ser = Buffer.from(''.concat(values), 'utf-8');

  try {
    keys = ked.keys;
    if (keys.length !== 1) throw new Error(`Basic derivation needs at most 1 key  got ${keys.length} keys instead`);
    verfer = new Verfer(null, keys[0]);
  } catch (exception) {
    throw new Error(`extracting public key = ${exception}`);
  }

  if (verfer.code() !== derivationCodes.oneCharCode.Ed25519) throw new Error(`Invalid derivation code = ${verfer.code()}`);
  if (!(seed || secret)) throw new Error('Missing seed or secret.');

  signer = new Signer(seed, derivationCodes.oneCharCode.Ed25519_Seed, true, libsodium, secret);
  if (verfer.raw().toString() !== (signer.verfer().raw()).toString()) throw new Error('Key in ked not match seed.');

  sigver = signer.sign(ser);
  return { raw: sigver.raw(), code: derivationCodes.twoCharCode.Ed25519 };
}

module.exports = { Prefixer };
