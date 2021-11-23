/* eslint-disable no-underscore-dangle */
const Base64 = require('urlsafe-base64');
const util = require('util');
const utf8 = require('utf8');
const {nabSextets, sceil, b2ToB64} = require('./utls');
const codeAndLength = require('./derivationCode&Length');
const { b64ToInt, intToB64 } = require('../help/stringToBinary');
const derivationCodeLength = require('./derivationCode&Length');

// const Bizes = ({b64ToB2(c): hs for c, hs in Sizes.items()})
/**
 * @description CRYPTOGRAPHC MATERIAL BASE CLASS
 * @subclasses  provides derivation codes and key event element context specific
 * @Properties
 *         .code  str derivation code to indicate cypher suite
        .raw   bytes crypto material only without code
        .pad  int number of pad chars given raw
        .qb64 str in Base64 with derivation code and crypto material
        .qb2  bytes in binary with derivation code and crypto material
 */
class Crymat {
  constructor(
    raw = null,
    qb64 = null,
    qb2 = null,
    code = codeAndLength.oneCharCode.Ed25519N,
    index = 0,
    qb64b = null,
  ) {
    /*
          Validate as fully qualified
        Parameters:
            raw is bytes of unqualified crypto material usable for crypto operations
            qb64 is str of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            code is str of derivation code

        When raw provided then validate that code is correct for length of raw
            and assign .raw
        Else when qb64 or qb2 provided extract and assign .raw and .code
        */
    if (raw) {
      console.log('length of raw is ==========>', raw.length);
      if (!(Buffer.isBuffer(raw) || Array.isArray(raw))) {
        throw new Error(`Not a bytes or bytearray, raw= ${raw}.`);
      }

      const pad = this._pad(raw);
      if (
        !(
          (pad === 1 &&
            Object.values(JSON.stringify(codeAndLength.CryOneSizes)).includes(
              code
            )) ||
          (pad === 2 &&
            Object.values(
              JSON.stringify(codeAndLength.CryTwoSizes).includes(code)
            )) ||
          (pad === 0 &&
            Object.values(
              JSON.stringify(codeAndLength.CryFourSizes).includes(code)
            ))
        )
      ) {
        throw new Error(`Wrong code= ${code} for raw= ${raw} .`);
      }
      if (
        (Object.values(codeAndLength.CryCntCodex).includes(code) &&
          index < 0) ||
        index > codeAndLength.CRYCNTMAX
      ) {
        throw new Error(`Invalid index=${index} for code=${code}.`);
      }

      raw = raw.slice(0, codeAndLength.cryAllRawSizes[code]);

      if (raw.length !== codeAndLength.cryAllRawSizes[code]) {
        throw new Error(`Unexpected raw size= ${raw.length} for code= ${code}"
        " not size= ${codeAndLength.cryAllRawSizes[code]}.`);
      }
      this.getCode = code;
      this.getIndex = index;
      console.log('Length of raw after slicing is ========>', raw.length);
      this.getRaw = raw; // crypto ops require bytes not bytearray
    } else if (qb64 != null) {
      qb64 = qb64.toString('utf-8');
      this.exfil(qb64);
    } else if (qb2 != null) {
      this.bexfil(qb2);
    } else {
      throw new Error('Improper initialization need either (raw and code) or qb64b or qb64 or qb2.');
    }
  }

  // eslint-disable-next-line no-underscore-dangle
  // eslint-disable-next-line class-methods-use-this
  _pad(raw) {
    const reminder = Buffer.byteLength(raw, 'binary') % 3; // length for bytes
    console.log('value of reminder is ==============>', reminder);
    if (reminder === 0) {
      return 0;
    }
    return 3 - reminder;
  }

  exfil(qb64) {
    const base64Pad = '=';
    let cs = 1; // code size
    let codeSlice = qb64.slice(0, cs);
    let index;

    if (Object.values(codeAndLength.oneCharCode).includes(codeSlice)) {
      qb64 = qb64.slice(0, codeAndLength.CryOneSizes[codeSlice]);
    } else if (codeSlice === codeAndLength.crySelectCodex.two) {
      cs += 1;
      codeSlice = qb64.slice(0, cs);

      if (!Object.values(codeAndLength.twoCharCode).includes(codeSlice)) {
        throw new Error(`Invalid derivation code = ${codeSlice} in ${qb64}.`);
      }

      qb64 = qb64.slice(0, codeAndLength.CryTwoSizes[codeSlice]);
    } else if (codeSlice === codeAndLength.crySelectCodex.four) {
      cs += 3;
      codeSlice = qb64.slice(0, cs);

      if (!Object.values(codeAndLength.fourCharCode).includes(codeSlice)) {
        throw new Error(`Invalid derivation code = ${codeSlice} in ${qb64}.`);
      }
      qb64 = qb64.slice(0, codeAndLength.CryFourSizes[codeSlice]);
    } else if (codeSlice === codeAndLength.crySelectCodex.dash) {
      cs += 1;
      codeSlice = qb64.slice(0, cs);

      if (!Object.values(codeAndLength.CryCntCodex).includes(codeSlice)) {
        throw new Error(`Invalid derivation code = ${codeSlice} in ${qb64}.`);
      }

      qb64 = qb64.slice(0, codeAndLength.CryCntSizes[codeSlice]);
      cs += 2; // increase code size
      index = b64ToInt(qb64.slice(cs - 2, cs));
      //  index = Object.keys(codeAndLength.b64ChrByIdx).find(key =>
      // codeAndLength.b64ChrByIdx[key] === qb64.slice(cs - 2, cs)) // last two characters for index
    } else {
      throw new Error(`Improperly coded material = ${qb64}`);
    }

    if (qb64.length !== codeAndLength.cryAllSizes[codeSlice]) {
      throw new Error(
        `Unexpected qb64 size= ${qb64.length} for code= ${codeSlice} not size= ${codeAndLength.cryAllSizes[codeSlice]}.`
      );
    }
    const derivedRaw = Base64.decode(
      qb64.slice(cs, qb64.length) + base64Pad.repeat(cs % 4).toString('utf-8')
    );

    if (derivedRaw.length !== Math.floor(((qb64.length - cs) * 3) / 4)) {
      throw new Error(`Improperly qualified material = ${qb64}`);
    }
    this.getCode = codeSlice;
    this.getRaw = Buffer.from(derivedRaw, 'binary'); // encode
    // eslint-disable-next-line radix
    this.getIndex = parseInt(index);
    this.getqb64 = qb64;
  }

  infil() {
    let l = null;
    let full = this.getCode;
    if (Object.values(codeAndLength.CryCntCodex).includes(this.getCode)) {
      l = codeAndLength.CryCntIdxSizes[this.getCode];
      full = `${this.getCode}${intToB64(this.getIndex, l)}`;
    }

    const pad = this.pad();
    // Validate pad for code length
    if (full.length % 4 !== pad) {
      throw new Error(
        `Invalid code = ${this.getCode} for converted raw pad = ${this.pad()}.`
      );
    }
    return full + Base64.encode(this.getRaw);
  }

  /**
         *  qb64 = Qualified Base64 version,this will return qualified base64 version assuming
             self.raw and self.code are correctly populated
         */
  qb64() {
    return this.infil();
  }

  /**
     * """
        Property qb64b:
        Returns Fully Qualified Base64 Version encoded as bytes
        Assumes self.raw and self.code are correctly populated
        """
     */
  qb64b() {
    return Buffer.from(this.qb64(), 'binary'); // encode
  }

  qb2() {
    /* Property qb2:
         Returns Fully Qualified Binary Version Bytes
         redo to use b64 to binary decode table since faster
         """
         # rewrite to do direct binary infiltration by
         # decode self.code as bits and prepend to self.raw
         */

    return Base64.decode(Buffer.from(this.infil(), 'binary')).toString();
    // check here
  }

  rawSize(cls, code) {
    [hs, ss, fs] = cls.Codes[code]; // get sizes
    return ((fs - (hs + ss)) * 3); // 4 )
  }

  raw() {
    return this.getRaw;
  }

  pad() {
    // eslint-disable-next-line no-underscore-dangle
    return this._pad(this.getRaw);
  }

  code() {
    return this.getCode;
  }

  index() {
    return this.getIndex;
  }

  /**
   *         Property transferable:
        Returns True if identifier does not have non-transferable derivation code,
                False otherwise
   */
  transferable() {
    return (this.getCode in derivationCodeLength.NonTransCodex);
  }

  digestive() {
    return (this.getCode in derivationCodeLength.digiCodex);
  }

  /**
   * Returns bytes of fully qualified base2 bytes, that is .qb2
        self.code converted to Base2 left shifted with pad bits
        equivalent of Base64 decode of .qb64 into .qb2
   */

  binfil() {
    const code = this.getCode;
    const index = this.getIndex;
    const raw = this.getRaw;

    let [hs, ss, fs] = this.Codes[code];
    const bs = hs + ss;

    if (!fs) {
      if (bs % 4) {
        throw new Error(`Whole code size not multiple of 4 for variable length material. bs= ${bs}.`);
      }
      fs = (index * 4) + bs;
    }
    if (index < 0 || index > (64 ** ss - 1)) {
      throw new Error(`Invalid index=${index} for code=${code}.`);
    }

    const codeHex = code.toString(16);
    const convertedHex = (intToB64(index, ss)).toString(16);
    const both = `${codeHex}${convertedHex}`;
    if (both.length !== bs) {
      throw new Error(`Mismatch code size = ${bs} with table = ${both.length}.`);
    }
    let n = sceil((bs * 3) / 4); // number of b2 bytes to hold b64 code + index
    const bcode = Buffer.from(b64ToInt(both), 'binary');
    const full = bcode + raw;
    const bfs = full.length;

    if (bfs % 3 || Math.floor(bfs * 4 / 3) != fs) {
      throw new Error(`Invalid code = ${both} for raw size= ${raw.length}.`);
    }
    const i = parseInt(bcode) << (2 * (bs % 4));
    return Buffer.from(i, 'binary');
  }

  /**
   * @description  Extracts self.code, self.index, and self.raw from qualified base2 bytes qb2
   */
  bexfil(qb2) {
    if (!qb2) {
      throw new Error('Empty material, Need more bytes.');
    }

    const first = nabSextets(qb2, 1);

    if (!(first in this.Bizes)) {
      if (first[0] == Buffer.from('\xf8', 'binary')) {
        throw new Error('Unexpected count code start while extracing Matter.');
      } else if (first[0] == Buffer.from('\xfc', 'binary')) {
        throw new Error('Unexpected  op code start while extracing Matter.');
      }
    } else {
      throw new Error(`Unsupported code start sextet= ${first}.`);
    }

    const cs = this.Bizes[first]; // get code hard size equvalent sextets
    const bcs = sceil(cs * (3 / 4)); // bcs is min bytes to hold cs sextets

    if (qb2.length < bcs) {
      throw new Error(`Need ${bcs - qb2.length} more bytes.`);
    }

    const hard = b2ToB64(qb2, cs); // extract and convert hard part of code

    if (!(hard in derivationCodeLength.Codes[hard])) {
      throw new Error(`Unsupported code = ${hard}.`);
    }
    const [hs, ss, fs] = derivationCodeLength.Codes[hard];
    const bs = hs + ss;
    // assumes that unit tests on Indexer and IndexerCodex ensure that
    // .Codes and .Sizes are well formed.
    // hs == cs and hs > 0 and ss > 0 and (fs >= hs + ss if fs is not None else True)

    const bbs = Math.ceil(bs * (3 / 4)); // bbs is min bytes to hold bs sextets

    if (qb2.length < bbs) {
      throw new Error(`Need ${bbs-(qb2).length} more bytes.`);
    }

    const both = b2ToB64(qb2, bs); // extract and convert both hard and soft part of code
    let index = b64ToInt(both.slice(hs, hs+ss)); // get index

    let bfs = sceil(fs * (3 / 4));// bfs is min bytes to hold fs sextets

    if (qb2.length < bfs) {
      throw new Error(`Need ${bbs - (qb2).length} more bytes.`);
    }

    qb2 = qb2.slice(0, bfs.length); // fully qualified primitive code plus material

    // right shift to right align raw material
    let i = parseInt(qb2); // int.from_bytes(qb2, 'big')
    i >>= 2 * (bs % 4);
    i = Buffer.from(i, 'binary');
    i.slice(0, bbs);
    const raw = i.slice(0, bbs); // # extract raw

    if (this.raw.length != (qb2.length - bbs)) {
      throw new Error(`Improperly qualified material = ${qb2}`);
    } // # exact lengths

    this.getCode = hard;
    this.getIndex = index;
    this.getRaw = raw;
  }
}

module.exports = { Crymat };
