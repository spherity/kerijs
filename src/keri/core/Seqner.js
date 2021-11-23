
const { allCharcodes , Codes } = require('./derivationCode&Length');
const {Matter, rawSize} = require('./matter')
var bigNum = require('bignum');
const { intToB64 } = require('../help/stringToBinary');
/**
 *  """
    Seqner is subclass of Matter, cryptographic material, for ordinal numbers
    such as sequence numbers or first seen ordering numbers.
    Seqner provides fully qualified format for ordinals (sequence numbers etc)
    when provided as attached cryptographic material elements.

    Useful when parsing attached receipt groupings with sn from stream or database

    Uses default initialization code = CryTwoDex.Salt_128
    Raises error on init if code not CryTwoDex.Salt_128

    Attributes:

    Inherited Properties:  (See Matter)
        .pad  is int number of pad chars given raw
        .code is  str derivation code to indicate cypher suite
        .raw is bytes crypto material only without code
        .index is int count of attached crypto material by context (receipts)
        .qb64 is str in Base64 fully qualified with derivation code + crypto mat
        .qb64b is bytes in Base64 fully qualified with derivation code + crypto mat
        .qb2  is bytes in binary with derivation code + crypto material
        .nontrans is Boolean, True when non-transferable derivation code False otherwise

    Properties:
        .sn is int sequence number
        .snh is hex string representation of sequence number no leading zeros

    Hidden:
        ._pad is method to compute  .pad property
        ._code is str value for .code property
        ._raw is bytes value for .raw property
        ._index is int value for .index property
        ._infil is method to compute fully qualified Base64 from .raw and .code
        ._exfil is method to extract .code and .raw from fully qualified Base64


 */
class Seqner extends Matter {


    /**
     *         Inhereited Parameters:  (see Matter)
            raw is bytes of unqualified crypto material usable for crypto operations
            qb64b is bytes of fully qualified crypto material
            qb64 is str or bytes  of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            code is str of derivation code
            index is int of count of attached receipts for CryCntDex codes
     */
constructor(raw=null, qb64b=null, qb64=null, qb2=null,code=allCharcodes.SALT_128, sn=null, snh=null,...kwa){

        if(sn == null){
            if(snh == null){
                sn = 0;
            }else {
                sn = parseInt(snh, 16)
            }
        }

        if((raw == null) &&  (qb64b == null) &&  (qb64 == null)  &&  (qb2 == null)){

            


         raw =  bigNum(sn).toBuffer({
                endian : 'big',
                size : rawSize(code), // number of bytes in each word
            })
            //raw = sn.to_bytes(Matter._rawSize(MtrDex.Salt_128), 'big')


        //  // let b64Sn = intToB64(sn)
        //    console.log("Value of sn = ",sn)
        // //    let intNum = bignum.fromBuffer(full)
        // //    let intNum1 = BigInt(intNum.toString())
        //     let p = Buffer.from(sn,'binary')
        //     p =  bignum.fromBuffer(Buffer.from(p,'binary'))
        //     //bignum.toBuffer(sn);
        //     console.log("Value of BigInt p = ", (bignum.fromBuffer(p)))
        //    // let i = bignum.fromBuffer(buf)
        //  //   let intNum1 = BigInt(p)
        //  console.log("p.toString() ================>",p.toString())
        //     var raw =   BigInt(p.toString());
        //     console.log("Value of bigNum raw = ",raw.toString())
        }
        console.log("value of raw and code = ",raw, '\n',code)
        super(raw,code, qb64b, qb64, qb2, ...kwa);

        if(this.code() != allCharcodes.SALT_128) {
            throw new Error(`Invalid code = ${this.code()} for SeqNumber.`)
        }
}


/**
 * Returns .raw converted to int
 */
sn(){
    let intNum = bigNum.fromBuffer(this.raw())
    console.log("Value of SN = ",bigNum.toNumber(intNum))
    return  bigNum.toNumber(intNum)
    
    //return int.from_bytes(self.raw, 'big')
}

/**
 * Returns .raw converted to hex str
 */
snh(){
 
    return (this.sn()).toString(16)
}

}


module.exports = {Seqner}