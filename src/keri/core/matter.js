const Base64 = require('urlsafe-base64');
const { allCharcodes , Codes } = require('./derivationCode&Length');
const { nabSextets, sceil, b2ToB64, Bizes, b2ToB64BigInt } = require('./utls');
const { b64ToInt } = require('../help/stringToBinary');
// eslint-disable-next-line no-undef
const derivationCodeLength = require('./derivationCode&Length');
const BigNum = require('bignum');
/**
 * @description   Matter is fully qualified cryptographic material primitive base class for
    non-indexed primitives.

    Sub classes are derivation code and key event element context specific.

    Includes the following attributes and properties:

    Attributes:

    Properties:
        .code is  str derivation code to indicate cypher suite
        .raw is bytes crypto material only without code
        .qb64 is str in Base64 fully qualified with derivation code + crypto mat
        .qb64b is bytes in Base64 fully qualified with derivation code + crypto mat
        .qb2  is bytes in binary with derivation code + crypto material
        .transferable is Boolean, True when transferable derivation code False otherwise
        .digestive is Boolean, True when digest derivation code False otherwise

        Needs either (raw and code) or qb64b or qb64 or qb2
        Otherwise raises EmptyMaterialError
        When raw and code provided then validate that code is correct for length of raw
            and assign .raw
        Else when qb64b or qb64 or qb2 provided extract and assign .raw and .code

 */
class Matter {
  /** Validate as fully qualified
     * @param {*} raw raw is bytes of unqualified crypto material usable for crypto operations
     * @param {*} code code is str of stable (hard) part of derivation code
     * @param {*} qb64b qb64b is bytes of fully qualified crypto material
     * @param {*} qb64 qb64 is str or bytes  of fully qualified crypto material
     * @param {*} qb2 qb2 is bytes of fully qualified crypto material
     */
  constructor(raw = null, code = allCharcodes.Ed25519N, qb64b = null, qb64 = null, qb2 = null) {
    console.log('Calling Constructor Value of Raw is ---------->', raw, code);
    if (raw != null) {
      if (!code) {
        throw new Error('Improper initialization need either (raw and code) or qb64b or qb64 or qb2.');
      }
      // console.log("Value of Raw is -----------_>",raw);
      if (!(Buffer.isBuffer(raw) || Array.isArray(raw))) {
        throw new Error(`Not a bytes or bytearray, raw= ${raw}.`);
      }
      
      if (!(Object.values(
        JSON.stringify(allCharcodes).includes(code),
      ))) {
        throw new Error(`Unsupported code= ${JSON.stringify(allCharcodes)}.`);
      }
      
      let getRawSize = rawSize(code);
      // console.log('value of rawSize =================>', getRawSize);
      raw = raw.slice(0, getRawSize); // copy only exact size from raw stream
      console.log("Length of Raw = ", raw.length , getRawSize, raw.toString());
      if (raw.length != getRawSize) {
        throw new Error(`Not enougth raw bytes for code= ${code} expected ${getRawSize} got ${raw.length}.`);
      }
      this.getCode = code;
      this.getRaw = raw; // crypto ops require bytes not bytearray
    } else if (qb64b != null) {
      this.exfil(qb64b);
    } else if (qb64 != null) {
      this.exfil(qb64);
    } else if (qb2 != null) {
      this.bexfil(qb2);
    } else {
      throw new Error(`Improper initialization need either (raw and code) or qb64b or qb64 or qb2. `);
    }
  }

  // eslint-disable-next-line class-methods-use-this
  exfil(qb64b) {

    console.log("Value of qb64 = ",qb64b)
    const BASE64_PAD = '=';
    if (!qb64b) {
      throw new Error('Empty material, Need more characters.');
    }

    const first = qb64b.slice(0, 1);
    if (first != null) {
      first.toString('utf-8');
    }
    if (!(first in derivationCodeLength.chrIntMapping)) {
      if (first[0] == '_') {
        throw new Error('Unexpected  op code start while extracing Matter.');
      } else if (first[0] == '-') {
        throw new Error('Unexpected count code start');
      }else {
        throw new Error(`Unsupported code start char= ${first}.`);
      }
    }
    let cs = derivationCodeLength.chrIntMapping[first]; // get hard code size
    if (qb64b.length < cs) {
      throw new Error(`Need ${cs - qb64b.length} more characters.`);
    }
    let code = qb64b.slice(0, cs);
    console.log("Value of code = ",code)
    if (code != null) {
      code = code.toString();
      if (!(code in derivationCodeLength.Codes)) {
        throw new Error(`Unsupported code = ${code}.`);
      }
    }
    let results = Codes[code];
    let bs = results.hs + results.ss; // both hs and ss
    // assumes that unit tests on Matter and MatterCodex ensure that
    // .Codes and .Sizes are well formed.
    // hs == cs and ss == 0 and not fs % 4 and hs > 0 and fs > hs
    console.log("Value of qb64b and fs are = ",qb64b.length , results.fs)
    if (qb64b.length < results.fs) {
      throw new Error(`Need ${results.fs - qb64b.length} more chars.`);
    }
    qb64b = qb64b.slice(0, results.fs);
    if (qb64b != null) {
      qb64b = Buffer.from(qb64b, 'binary');
    }

    // strip off prepended code and append pad characters
    const ps = bs % 4 // pad size ps = bs mod 4
    const base = Buffer.concat([qb64b.slice(bs, qb64b.length) , Buffer.from(BASE64_PAD.repeat(ps).toString('utf-8') , 'binary')]);
    console.log("Value of qb64b.slice(bs, qb64b.length) = ",qb64b.slice(bs, qb64b.length))
    console.log("Value of Base = ",Base64.decode(base))
    const rawData = Base64.decode(base);
    console.log("Length of Raw and qb64 are = ",rawData, '\n\n',Math.floor((qb64b.length - bs) * 3 / 4) )
    if (rawData.length != (Math.floor((qb64b.length - bs) * 3 / 4))){
      throw new Error(`Improperly qualified material = ${qb64b}`);
    } // exact length
    this.getCode = code;
    this.getRaw = rawData;
  }

  binfil() {
    const code = this.getCode;
    const index = this.getIndex;
    const raw = this.getRaw;

    let response = Codes[code];
    const bs = response.hs + response.ss;
    console.log("Value of B =",bs)
    console.log("Value of Code =",code)
    if (code.length != bs) {
      // if (bs % 4) {
        throw new Error(`Mismatch code size = ${bs} with table = ${code.length}.`);
      // }

    }
    let n = sceil(bs * 3 / 4);
  //  var bcode = Buffer.from(b64ToInt(code).toString(),'binary' ); // right aligned b2 code
    var bcode = BigNum.toBuffer(b64ToInt(code))
    // console.log("value of b64ToInt(code) =",bcode,'======',bignum.fromBuffer(bcode))
      console.log("Value of Bcode = ",Base64.encode(bcode))
    console.log("Required Number of B2 bytes are : ",n)
  //   let buf1 = Buffer.allocUnsafe(32)
  //   buf1.writeUInt32BE(b64ToInt(code),0)
  //   console.log("Value of Buf1 =",buf1)
  //   console.log("Value of n =",n)
  //  // const view = new DataView(bcode)
  //     let a1 = Buffer.from((b64ToInt(code)).toString(),'binary', n)
  //   console.log("Value of bcode =",a1, raw)
    const full = Buffer.concat([bcode  , raw]); 
    // intNum.toString() + intNum1.toString()
    // console.log("Value of full = ",(full).length , raw.length)
    // //Buffer.concat([a1 , raw]);
    // console.log("Value of full =",full)
    const bfs = full.length;
    console.log("Base64 Value of full = ",Base64.encode(full))
    console.log("Value of bfs =",bfs)
    if (bfs % 3 || Math.floor(bfs * 4 / 3) != response.fs) {
      throw new Error(`Invalid code = ${code} for raw size= ${raw.length}.`);
    }
    //full = parseInt(full)
    console.log("Value of Bs = ",bs)
    let intNum = BigNum.fromBuffer(full)
    let intNum1 = BigInt(intNum.toString())
    let intNum2 = BigInt((2 * (bs % 4)))
     console.log("intNum.toString() ==============>",intNum1)
    // let a = BigInt()
    // console.log("Value of full = ",(full).length , raw.length)

   // getShiftedString(intNum.toString() ,(2 * (bs % 4),0)
   let bigNum = BigInt(intNum)
    const i = intNum1 << intNum2;
    //leftShifting(intNum.toString() ,(2 * (bs % 4),0))
    //
    console.log("Value of intNum = ",i.toString())   //intNum.toString()
    console.log("Value of i = ", i)
    console.log("Converting  back to bignum",BigNum.toString(i.toString()))

    // const arr = Array.from(i.toString())
console.log("Value of array is ",BigNum.toBuffer(i.toString()))
console.log("Base64 of bigNum = ",Base64.encode(BigNum.toBuffer(i)))
    return BigNum.toBuffer(i)
  // let bfs = full.length
   // Buffer.from(full , 'binary')// 0x12345678 = 305419896
   //console.log("BUF bytelength = ",Buffer.byteLength(buf))
   //buf = buf.readInt32BE(0);
//    console.log("value of BUF = ",buf);
//    console.log("LEft padding value = ",(2 * (bs % 4)));
//  i = parseInt(buf)  << (2 * (bs % 4))
// console.log("value of I = ",i.toString())
// let abc = Buffer.allocUnsafe(32)
// // abc.writeUInt32BE(bfs,0)
//     console.log("Returned value is = ",(abc.writeInt32BE(i,0))) // 305419896
    // return buf.from(i, 'binary');
    // if (index < 0 || index > (64 ** ss - 1)) {
    //   throw new Error(`Invalid index=${index} for code=${code}.`);
    // }

    // const codeHex = code.toString(16);
    // const convertedHex = (intToB64(index, ss)).toString(16);
    // const both = `${codeHex}${convertedHex}`;
    // if (both.length !== bs) {
    //   throw new Error(`Mismatch code size = ${bs} with table = ${both.length}.`);
    // }
    // let n = sceil((bs * 3) / 4); // number of b2 bytes to hold b64 code + index
    // const bcode = Buffer.from(b64ToInt(both), 'binary');
    // const full = bcode + raw;
    // const bfs = full.length;

    // if (bfs % 3 || Math.floor(bfs * 4 / 3) != fs) {
    //   throw new Error(`Invalid code = ${both} for raw size= ${raw.length}.`);
    // }
    // const i = parseInt(bcode) << (2 * (bs % 4));
    // return Buffer.from(i, 'binary');
  }

  /**
   * @description  Extracts self.code, self.index, and self.raw from qualified base2 bytes qb2
   */
  bexfil(qb2) {
    if (!qb2) {
      throw new Error('Empty material, Need more bytes.');
    }

    const first = nabSextets(qb2, 1);
    console.log("Value of first is = ",first)
      this.Bizes = Bizes
      let keys = []
       for(let key in Object.keys(this.Bizes)){ keys.push(Object.keys(this.Bizes)[key])}
      for(let key in keys){
        console.log("keys[key].toString() ====================>",keys)
        if(!keys[key].includes(first.toString())){
        console.log("keys[key].toString() != first.toString() ================>",keys[key].includes(first.toString()))
        if (first[0] == Buffer.from('\xf8', 'binary')) {
          throw new Error('Unexpected count code start while extracing Matter.');
        } else if (first[0] == Buffer.from('\xfc', 'binary')) {
          throw new Error('Unexpected  op code start while extracing Matter.');
        }else {
          throw new Error(`Unsupported code start sextet= ${first}.`);
        }
      }}
    console.log("Value of First = ",Object.keys(this.Bizes).includes(first.toString()),'/n', Base64.encode(first), '\n', Object.keys(this.Bizes)[52])
    console.log("Value of Bizes is ================>",Buffer.from('\xd0', 'binary').toString())
    // if (!(Object.keys(this.Bizes).includes(first.toString()))) {
    //   if (first[0] == Buffer.from('\xf8', 'binary')) {
    //     throw new Error('Unexpected count code start while extracing Matter.');
    //   } else if (first[0] == Buffer.from('\xfc', 'binary')) {
    //     throw new Error('Unexpected  op code start while extracing Matter.');
    //   }else {
    //     throw new Error(`Unsupported code start sextet= ${first}.`);
    //   }
    // } 

    const cs = this.Bizes[first]; // get code hard size equvalent sextets
    const bcs = sceil(cs * (3 / 4)); // bcs is min bytes to hold cs sextets

    if (qb2.length < bcs) {
      throw new Error(`Need ${bcs - qb2.length} more bytes.`);
    }

    
    const hard = b2ToB64BigInt(qb2, cs); // extract and convert hard part of code
    console.log("Value of Hard  = ",hard)
    if (!(Object.keys(derivationCodeLength.Codes).includes(hard))) {   //derivationCodeLength.Codes[hard])
      throw new Error(`Unsupported code = ${hard}.`);
    }
    let a = derivationCodeLength.Codes[hard]
    console.log("Valur of a = ",a   )
    const response = derivationCodeLength.Codes[hard];
    console.log(response)
    const bs = response.hs + response.ss;
    // assumes that unit tests on Indexer and IndexerCodex ensure that
    // .Codes and .Sizes are well formed.
    // hs == cs and hs > 0 and ss > 0 and (fs >= hs + ss if fs is not None else True)

    const bbs = Math.ceil(bs * (3 / 4)); // bbs is min bytes to hold bs sextets

    if (qb2.length < bbs) {
      throw new Error(`Need ${bbs-(qb2).length} more bytes.`);
    }
    
    const both = b2ToB64BigInt(qb2, bs); // extract and convert both hard and soft part of code
    let index = b64ToInt(both.slice(response.hs, response.hs+ response.ss)); // get index

    let bfs = sceil(response.fs * (3 / 4));// bfs is min bytes to hold fs sextets
    console.log("vaalue of bbs = ",bbs , ' bs =', bs, " code = ",both, ' bfs = ',bfs)
    if (qb2.length < bfs) {
      throw new Error(`Need ${bbs - (qb2).length} more bytes.`);
    }
    console.log("qb2 Value of qb2 = ",qb2)
    qb2 = qb2.slice(0, bfs); //BigInt(qb2) // fully qualified primitive code plus material

    // right shift to right align raw material
    console.log("qb2 Value of qb2 = ",qb2)
    let i =    BigNum.fromBuffer(qb2) //parseInt(qb2); // int.from_bytes(qb2, 'big')
    console.log("qb2 Value of i = ",i.toString())
    let j =BigInt(i.toString())
   j >>= BigInt(2 * (bs % 4));
    i = BigNum.toBuffer(j)
  
  //  i.slice(0, bbs);
    const raw = i.slice(bbs, i.length); // # extract raw
    console.log("Value of qb2  before comparing length is =", (raw).length , '\n\n',(qb2.length - bbs) ,'\n\n', bbs)
    if ((raw).length != (qb2.length - bbs)) {
      throw new Error(`Improperly qualified material = ${qb2}`);
    } // # exact lengths

    this.getCode = hard;
    this.getIndex = index;
    this.getRaw = raw;
  }

  /**
   *         Property transferable:
        Returns True if identifier does not have non-transferable derivation code,
                False otherwise
   */
  transferable() {
    console.log("TRUE OR FALSE ",!(this.getCode in derivationCodeLength.digiCodex))
    return (!(this.getCode in derivationCodeLength.digiCodex));
  }

  digestive() {
    console.log("TRUE OR FALSE ",(this.getCode in derivationCodeLength.digiCodex))
    return (this.getCode in derivationCodeLength.digiCodex);
  }

  code() {
    return this.getCode;
  }

  raw() {
    console.log('Value of Raw is =======', this.getRaw);
    return this.getRaw;
  }

  /**
   * @description         Returns Fully Qualified Base64 Version encoded as bytes
                          Assumes self.raw and self.code are correctly populated
   */
  qb64b() {
    return this.infil();
  }

  /**
   * @description   Returns Fully Qualified Base64 Version
                    Assumes self.raw and self.code are correctly populated
   */
  qb64() {
    return (this.qb64b()).toString();
  }

  /**
   * @description Returns Fully Qualified Binary Version Bytes
   */
  qb2() {
    return this.binfil();
  }

  /**
   * @description       Returns bytes of fully qualified base64 characters
                        self.code + converted self.raw to Base64 with pad chars stripped
   */
  infil() {
    const code = this.getCode; // codex value
    let raw = this.getRaw; //  bytes or bytearray
    console.log("Raw length = ",raw.length)
    const ps = (3 - (raw.length % 3)) % 3; // pad size
    // check valid pad size for code size
    console.log('Value of Raw insde infil is =========>', raw);
    console.log('Value of ps is =========>', ps);
    if (code.length % 4 != ps) {
      throw new Error(`Invalid code = ${code} for converted raw pad size= ${ps}.`);
    }
  console.log(" ps ================>", ps);
    if (ps) {
      console.log("Value of PS is =======>",ps , Base64.encode(raw));
      raw = Buffer.from(raw).toString('base64');
      raw = raw.slice(0, -ps);
      console.log(" Base64.encode(raw) ================>", raw);
    } else {
     {};
    }
    console.log("Valeu of rawi = ",raw)
    console.log("Base64.encode(raw) ___________________>",(Buffer.concat([Buffer.from(code,'binary'),Buffer.from(raw,'binary')])).toString());
    return Buffer.concat([Buffer.from(code,'binary'),Buffer.from(Base64.encode(raw),'binary')])   //code + ;
  }
}

/**
 * @description Returns raw size in bytes for a given code
 * @param {*} code
 */
function rawSize(code) {
  console.log('code ==================>', Codes.B);
  const response = Codes[code]; // get sizes
  return Math.floor((response.fs - (response.hs + response.ss)) * 3 / 4);
}

module.exports = { Matter ,rawSize };
