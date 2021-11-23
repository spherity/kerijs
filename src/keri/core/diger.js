const blake3 = require('blake3');
const blakejs = require('blakejs')
var  { createBLAKE3, createBLAKE2b } = require('hash-wasm');
const crypto = require("crypto")
const utf8 = require('utf8');
const { Matter } = require('./matter');
const derivationCode = require('./derivationCode&Length');

/**
 * @description :     Diger is Matter subclass with method to verify digest of serialization
    using  .raw as digest and .code for digest algorithm.

    See Matter for inherited attributes and properties:

    Inherited Properties:
        .pad  is int number of pad chars given raw
        .code is  str derivation code to indicate cypher suite
        .raw is bytes crypto material only without code
        .index is int count of attached crypto material by context (receipts)
        .qb64 is str in Base64 fully qualified with derivation code + crypto mat
        .qb64b is bytes in Base64 fully qualified with derivation code + crypto mat
        .qb2  is bytes in binary with derivation code + crypto material
        .nontrans is Boolean, True when non-transferable derivation code False otherwise

    Methods:
        verify: verifies digest given ser
        compare: compares provide digest given ser to this digest of ser.
                enables digest agility of different digest algos to compare.
 *
 */
class Diger extends Matter {
  // This constructor will assign digest verification function to ._verify\


  constructor(raw = null, ser = null, code = derivationCode.oneCharCode.Blake3_256,   blakeInstance, ...kwa) {
    
    // try {
    //   let hasha =   blake2b()
    //     console.log("hasha =================+>",hasha.then(response=>{
    //       return response
    //     }));
    //   hasha.update(ser)
    //   console.log("blake2b(ser) ==========================>",hasha.update(ser));
    //   super(raw, code, ...kwa);
    // } catch (error) {
    //   if (!ser) {
    //     throw new Error(error);
    //   }
    //   if (code == derivationCode.oneCharCode.Blake3_256) {
    //     const hasher = blake3.createHash();
    //     // let dig = blake3.hash(ser);
    //     var dig = hasher.update(ser).digest('');
    //     // super(dig , null , null, code,0);
    //   } else if(code ==derivationCode.oneCharCode.Blake2b_256){
    //     console.log("We are inside BLAKE2B ###################################>")
    //     dig = blake2b(ser);
    //   }else if(code ==derivationCode.oneCharCode.Blake2s_256){
    //     dig = blakejs.blake2s(ser,null,32)
    //   }else if(code ==derivationCode.oneCharCode.SHA3_256){
    //     dig = crypto.createHash("sha3-256").update(key).digest("hex")
    //   }else if(code ==derivationCode.oneCharCode.SHA2_256){
    //     dig = crypto.createHash("sha256").update(key).digest("hex")
    //   }else {
    //     throw new Error(`Unsupported code = ${code} for digester.`);
    //   }

    //   super(dig, code, null, ...kwa);
    // }

    // if (code == derivationCode.oneCharCode.Blake3_256) {
    //   this.verifyFunc = this.blake3_256;
    // }else if(code ==derivationCode.oneCharCode.Blake2b_256){
    //   this.verifyFunc = this.blake2b_256;
    // }else if(code ==derivationCode.oneCharCode.Blake2s_256){
    //   this.verifyFunc = this.blake2s_256;
    // }else if(code ==derivationCode.oneCharCode.SHA3_256){
    //   this.verifyFunc = this.sha3_256;
    // }else if(code ==derivationCode.oneCharCode.SHA2_256){
    //   this.verifyFunc = this.sha2_256;
    // } else {
    //   throw new Error(`Unsupported code = ${code} for digester.`); 
    // }
    
      try {
        console.log("INSIDE TRY",raw)
        // const   hasher =  createBLAKE3(16);
        // console.log("Diger.blake2 ====================>",blakeInstance);
      //   blakeInstance.blake2.update('abc');
      //   // console.log("Hasher.digest = ============>",blakeInstance.blake2.digest())
      //  let dig =  blakeInstance.blake2.digest()
       
      //   console.log("Value of Digest is = ",raw)
        super(raw, code, ...kwa);
        this.blakeInstance = blakeInstance
        
      } catch (error) {
        if (!ser) {
          throw new Error(error);
        }
        if (code == derivationCode.oneCharCode.Blake3_256) {

          // const hasher = blake3.createHash();
          // // let dig = blake3.hash(ser);
          // var dig = hasher.update(ser).digest('');
          // // super(dig , null , null, code,0);
             //   const   hasher =  createBLAKE3(16);
                // blakeInstance.blake3.update(ser);
                // console.log("Hasher.digest = ============>",blakeInstance.blake3.digest())
         var  dig =  blakeInstance.blake3.init()
         dig =  dig.update(ser).digest()
            dig = Buffer.from(dig,'binary')
        } else if(code ==derivationCode.oneCharCode.Blake2b_256){
          console.log("We are inside BLAKE2B ###################################>")
          dig =  blakeInstance.blake2b.init()
         dig =  dig.update(ser).digest()
          dig = Buffer.from(dig,'binary')
          //blake2b(ser);
        }else if(code ==derivationCode.oneCharCode.Blake2s_256){
          dig =  blakeInstance.blake2s.init()
          dig =  dig.update(ser).digest()
          dig = Buffer.from(dig,'binary')
        }else if(code ==derivationCode.oneCharCode.SHA3_256){
          dig = crypto.createHash("sha3-256").update(ser).digest()
          dig = Buffer.from(dig,'binary')
        }else if(code ==derivationCode.oneCharCode.SHA2_256){
          dig = crypto.createHash("sha256").update(ser).digest()
          dig = Buffer.from(dig,'binary')
        }else {
          throw new Error(`Unsupported code = ${code} for digester.`);
        }
        super(dig, code, ...kwa);
        //super(dig, code, null, ...kwa);
        this.blakeInstance = blakeInstance
      }
  
      if (code == derivationCode.oneCharCode.Blake3_256) {
        this.verifyFunc = this.blake3_256;
      }else if(code ==derivationCode.oneCharCode.Blake2b_256){
        this.verifyFunc = this.blake2b_256;
      }else if(code ==derivationCode.oneCharCode.Blake2s_256){
        console.log("INSIDE Blake2s_256 ========================>")
        this.verifyFunc = this.blake2s_256;
      }else if(code ==derivationCode.oneCharCode.SHA3_256){
        this.verifyFunc = this.sha3_256;
      }else if(code ==derivationCode.oneCharCode.SHA2_256){
        this.verifyFunc = this.sha2_256;
      } else {
        throw new Error(`Unsupported code = ${code} for digester.`); 
      }
    
  }

  static async initBlake() {
    
 const blake2b =   await createBLAKE2b(128);
  const blake3 = await createBLAKE3(256);
  const blake2s = await createBLAKE2b(128);
     return {blake2b :blake2b, blake2s :blake2s , blake3 : blake3}

  }

  /**
     * 
     * @param {bytes} ser  serialization bytes
     * @description  This method will return true if digest of bytes serialization ser matches .raw
     * using .raw as reference digest for ._verify digest algorithm determined
        by .code
     */
    verify(ser) {
    return this.verifyFunc(ser, this.raw());
  }


  blake3_256(ser, raw) {
  
   let hash_ER = this.blakeInstance.blake3.init();
   hash_ER =  hash_ER.update(ser).digest();
   console.log("hash_ER =======================>",hash_ER.toString(), raw.toString())
//let    hash_ER =   this.blakeInstance.blake3.update(ser).digest();
    // hash_ER =   hash_ER.digest()
    // let dig = blake3.hash(ser);
  //  console.log("Checking if the condition is true or not ", this.blakeInstance.blake3.update(ser).digest() , raw.toString())
    return (hash_ER.toString() == raw.toString());
  }

  blake2b_256(ser, raw) {

    let hash2b = this.blakeInstance.blake2b.init();
    hash2b =  hash2b.update(ser).digest();
    console.log("hash_ER =======================>",hash2b.toString(), raw.toString())
    return (hash2b.toString() == raw.toString());
  }

  blake2s_256(ser, raw) {

    // const hasher = blake3.createHash();
    // let dig = blake3.hash(ser);
    //let digest = blakejs.blake2s(ser,null,32);
    let hash2s = this.blakeInstance.blake2s.init();
    hash2s =  hash2s.update(ser).digest();
    console.log("hash_ER =======================>",(hash2s.toString()), raw.toString())
    return (hash2s.toString() == raw.toString());
  }

  sha3_256(ser, raw) {

    // const hasher = blake3.createHash();
    // let dig = blake3.hash(ser);
    let digest = crypto.createHash("sha3-256").update(ser).digest();
  // digest = digest.slice(0,32);
    console.log("Value of Digest and raw are = ",digest, raw);
    return (digest.toString() == raw.toString());
  }

  sha2_256(ser, raw) {

    // const hasher = blake3.createHash();
    // let dig = blake3.hash(ser);
    let digest = crypto.createHash("sha256").update(ser).digest()
    console.log("Value of Digest and raw are = ",digest.toString(), raw.toString());
    return (digest.toString() == raw.toString());
  }



    
    /**
   * @description  """
        Returns True  if dig and either .diger.qb64 or .diger.qb64b match or
            if both .diger.raw and dig are valid digests of self.raw
            Otherwise returns False

        Convenience method to allow comparison of own .diger digest self.raw
        with some other purported digest of self.raw
        If both match then as optimization returns True and does not verify either
          as digest of ser
        If both have same code but do not match then as optimization returns False
           and does not verify if either is digest of ser
        But if both do not match then recalcs both digests to verify they
        they are both digests of ser with or without matching codes.
        """
   * @param {*} dig  // dig is qb64b or qb64 digest of ser to compare with .diger.raw
   * @param {*} diger  // diger is Diger instance of digest of ser to compare with .diger.raw
   */
  compare(ser, dig = null, diger = null) {
    if (dig) {
      dig = Buffer.from(dig, 'binary'); // Make bytes
      if (dig == this.qb64b()) { //   matching
        return true;
      }
      let kwa = [dig]
      diger = new Diger(null, null, derivationCode.oneCharCode.Blake3_256, this.blakeInstance, ...kwa);
    } else if (diger) {
      if (diger.qb64b() == this.qb64b()) {
        return true;
      }
    } else {
      throw new Error('Both dig and diger may not be None.');
    }
    if (diger.code() == this.code()) {
      return false;
    }
    if (diger.verify(ser) && this.verify(ser)) {
      return true;
    }
    return false;
  }


}


//  function blake2b(){
//   // return  new Promise((resolve,reject)=>{
//   //   try{
//   //  let hashA =  createBLAKE2b(128)

//   //     setTimeout(resolve(hashA,200000))
//   //   }catch(error){
//   //     reject(error)
//   //   }
   
//   // })


//   var p2 = Promise.resolve(createBLAKE2b(128));
// return p2.then(function(v) {
//   console.log("Value of V ====================>",v);
//   return v
// }, function(e) {
//   console.error(e); // TypeError: Throwing
//   return e
// });
// }
module.exports = { Diger };
