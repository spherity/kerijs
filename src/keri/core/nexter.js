const _ = require('lodash');
const { Diger } = require('./diger');
const {Tholder} = require('./tHolder')
const {Matter, rawSize} = require('./matter')
const BigNum = require('bignum');
const codeAndLength = require('./derivationCode&Length');

let getSer;
let getSith;
let getKeys;
/**
 * @description  Nexter is Matter subclass with support to derive itself from
    next sith and next keys given code.

    See Diger for inherited attributes and properties:
 */

class Nexter extends Matter {
  /**
     *
 Assign digest verification function to ._verify

        See CryMat for inherited parameters

        Parameters:
           ser is bytes serialization from which raw is computed if not raw
           sith is int threshold or lowercase hex str no leading zeros
           keys is list of keys each is qb64 public key str

           Raises error if not any of raw, ser, keys, ked

           if not raw and not ser
               If keys not provided
                  get keys from ked

           If sith not provided
               get sith from ked
               but if not ked then compute sith as simple majority of keys
     */
  constructor(limen=null, sith=null, digs=null, keys=null, ked=null,code=codeAndLength.oneCharCode.Blake3_256, blakeInstance, ...kwa
  ) {
    try {
      super(...kwa);
    } catch (error) {
      console.log("Inside Catch")
      if (!digs && !keys && !ked) {
        throw error;
      }
      if(code == codeAndLength.oneCharCode.Blake3_256){
        var digest =   blakeInstance.blake3.init();
      }
   //  else {throw new Error(`Unsupported code = ${code} for nexter.`)}
      raw = deriveSer(code=code, limen=limen, sith=sith, digs=digs, keys=keys, ked=ked);
     // [getSer, getSith, getKeys] = deriveSer(sith, keys, ked);

      super(raw, code,...kwa);
      this.digest = digest;
    }
    if (this.getCode == codeAndLength.oneCharCode.Blake3_256) {
      console.log("blakeInstance ===============>",blakeInstance.blake3)
      this.digest = blakeInstance.blake3.init();
    } else throw new Error(`Unsupported code = ${code} for nexter.`);
   
  }

  /**
   * """ Property ._sith getter """
   */
  sith() {
    return this.getSith;
  }

  /**
   * """ Property ._keys getter """
   */
  keys() {
    return this.getKeys;
  }

  // eslint-disable-next-line class-methods-use-this
  derive(code, limen=null, sith=null, digs=null, keys=null, ked=null) {
    return deriveSer(code, limen=null, sith=null, digs=null, keys=null, ked=null);
  }

  /**
     * @description    Returns True if digest of bytes serialization ser matches .raw
        using .raw as reference digest for ._verify digest algorithm determined
        by .code  If ser not provided then extract ser from either (sith, keys) or ked
     * @param {*} ser
     * @param {*} sith
     * @param {*} keys
     * @param {*} ked
     */
  verify(raw=Buffer.from('','binary'), limen=null, sith=null, digs=null, keys=null, ked=null
    
  ) {

    if (!raw) {
      raw = this.derive(code=this.getCode, limen=limen, sith=sith, digs=digs,keys=keys, ked=ked);
    }
    console.log("Value or raw and this raw = ",(raw.toString() == (this.raw()).toString()))
    return (raw.toString() == (this.raw()).toString())
    //this.verifyFunc(derivedSer, this.raw());
  }


  static async initBlake() {
    
    const blake2b =   await createBLAKE2b(128);
     const blake3 = await createBLAKE3(256);
     const blake2s = await createBLAKE2b(128);
        return {blake2b :blake2b, blake2s :blake2s , blake3 : blake3}
   
     }
}

/**
*
@description Returns serialization derived from sith, keys, or ked
*/
function  deriveSer(code, limen=null, sith=null, digs=null, keys=null, ked=null, blakeInstance) {
  if(!digs){
  if (!keys) {
    try {
      keys = ked.k;
    } catch (error) {
      throw new Error(`Error extracting keys from ked = ${error}`);
    }
  }
  if (!keys) throw new Error('Empty keys.');
  for(let key in keys){
    keydigs = this.digest(keys[key])
  }
}else {
  let kwa = null
  let digers = []
  for(let dig in digs){
    kwa = [null,digs[dig]]
     digers = [new Diger(null,null,codeAndLength.oneCharCode.Blake3_256, blakeInstance, ...kwa)]

    for(let diger in digers){
      if(digers[diger].code() != code){
        throw new Error(`Mismatch of public key digest code = ${digers[diger].code} for next digest code = ${code}.`)
      }
    }}
        for(let diger in digers){
          keydigs = [digers[diger].raw()]
        }
    
  }

  if(limen == null){
    if(sith == null){
      try{
        // limen = Tholder(sith=sith).limen
       sith = ked["kt"]
      }catch(error){
          // throw new Error(error);
          let num = Math.max(1, Math.ceil((keydigs).length / 2))
          sith = num.toString(16)
      }
    }
    limen = new Tholder(sith).limen
  }

//   let i =    BigNum.fromBuffer(qb2) //parseInt(qb2); // int.from_bytes(qb2, 'big')
//   console.log("qb2 Value of i = ",i.toString())
//   let j =BigInt(i.toString())
//  j >>= BigInt(2 * (bs % 4));
//   i = BigNum.toBuffer(j)
for(let keydig in keydigs){
 let kints = BigNum.fromBuffer(keydig)
  kints =BigInt(kints.toString())
}
 // kints = [int.from_bytes(keydig, 'big') for keydig in keydigs]
  console.log("This Digest ===========================>",this.digest)
 let sint = BigNum.fromBuffer(this.digest(Buffer.from(limen,'binary')))
 sint =BigInt(sint.toString())
 //int.from_bytes(self._digest(limen.encode("utf-8")), 'big')
  for (let kint in kints){
    sint = Math.pow(sint,kints[kint] )
    sint ^= kints[kint]   //# xor together
  }
      
  // bignum.toBuffer(Matter.raw(code))
  
  return  BigNum(sint).toBuffer({
    endian : 'big',
    size : rawSize(code), // number of bytes in each word
})

  // kints = [int.from_bytes(keydig, 'big') for keydig in keydigs]
  //   sint = int.from_bytes(self._digest(limen.encode("utf-8")), 'big')
  //   for kint in kints:
  //       sint ^= kint  # xor together

    //return (sint.to_bytes(Matter._rawSize(code), 'big'))
 // keydigs = [self._digest(key.encode("utf-8")) for key in keys]
  // if (!sith) {
  //   try {
  //     sith = ked.sith;
  //   } catch (error) {
  //     sith = Math.max(1, Math.ceil(keys.length / 2));
  //   }
  // }
  // if (sith instanceof Array) {
  //   throw new Error(`List form of sith = ${sith} not yet supporte`);
  // } else {
  //   try {
  //     sith = parseInt(sith, 16);
  //   } catch (error) { throw new Error(error); }
  //   sith = Math.max(1, sith);
  //   sith = sith.toString(16);
  // }

  // nxts = [Buffer.from(sith, 'binary')]; // create list to concatenate for hashing   sith.toString("utf-8")
  // keys.forEach((key) => {
  //   nxts.push(Buffer.from(key, 'binary'));
  // });
  // getSer = Buffer.from(nxts.join(''), 'binary');

  // return [getSer, sith, keys];
}


/**
 * @description  Returns digest of raw using Blake3_256
 * @param {*} raw  raw is bytes serialization of nxt raw
 */
function blake3_256(raw){

  const hasher = blake3.createHash();;
let dig = hasher.update(ser).digest('');
    return dig
}

module.exports = { Nexter };
