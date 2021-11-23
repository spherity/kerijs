
const { allCharcodes , Codes } = require('./derivationCode&Length');
const {Matter, rawSize} = require('./matter');
var {Signer} = require('./signer')
const libsodium = require('libsodium-wrappers-sumo');
const { Tierage } = require('./utls');

/**
 *    """
    Salter is Matter subclass to maintain random salt for secrets (private keys)
    Its .raw is random salt, .code as cipher suite for salt

    Attributes:
        .level is str security level code. Provides default level

    Inherited Properties
        .pad  is int number of pad chars given raw
        .code is  str derivation code to indicate cypher suite
        .raw is bytes crypto material only without code
        .index is int count of attached crypto material by context (receipts)
        .qb64 is str in Base64 fully qualified with derivation code + crypto mat
        .qb64b is bytes in Base64 fully qualified with derivation code + crypto mat
        .qb2  is bytes in binary with derivation code + crypto material
        .nontrans is Boolean, True when non-transferable derivation code False otherwise
 */
class Salter extends Matter {


    /**
     * 
    raw is bytes of unqualified crypto material usable for crypto operations
            qb64b is bytes of fully qualified crypto material
            qb64 is str or bytes  of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            code is str of derivation code
            index is int of count of attached receipts for CryCntDex codes
     */
    constructor(raw=null, code=allCharcodes.SALT_128, tier=null, ...kwa){


        try{
            super(raw=raw, code=code, ...kwa)
        }catch(error){
            if (code == allCharcodes.Salt_128){
                
                raw = libsodium.randombytes_buf(libsodium.crypto_pwhash_SALTBYTES)
                 super(raw=raw, code=code, ...kwa)
            }
            
        else{
            throw new Error(`Unsupported salter code = ${code}.`)
        
        }
            
        }

        if(!bject.values(allCharcodes.SALT_128).includes(this.getCode)){
            throw new Error(`"Unsupported salter code = ${this.getCode}."`)
        }
    }

    static async initLibsodium() {
        await libsodium.ready;
      }
    

      signer(path="", tier=null, code=allCharcodes.Ed25519_Seed,transferable=true, temp=false){
          if(tier == null){
              tier = this.tier
          }
          if(temp){
          let  opslimit = libsodium.crypto_pwhash_OPSLIMIT_MIN
          let  memlimit = libsodium.crypto_pwhash_MEMLIMIT_MIN
          }else{
              if(tier ==Tierage.low ){
                opslimit = libsodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
                memlimit = libsodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
              }else if(tier ==Tierage.med){
                opslimit = libsodium.crypto_pwhash_OPSLIMIT_MODERATE
                memlimit = libsodium.crypto_pwhash_MEMLIMIT_MODERATE
              }else if(tier ==Tierage.high){

                opslimit = libsodium.crypto_pwhash_OPSLIMIT_SENSITIVE
                memlimit = libsodium.crypto_pwhash_MEMLIMIT_SENSITIVE
              }else {
                  throw new Error(`Unsupported security tier = ${tier}.`)
              }
          }

          // stretch algorithm is argon2id
        const  seed = libsodium.crypto_pwhash(outlen=rawSize(code),
                                        passwd=path,
                                        salt=this.raw(),
                                        opslimit=opslimit,
                                        memlimit=memlimit,
                                        alg=libsodium.crypto_pwhash_ALG_DEFAULT)
                                        return ( new  Signer(seed, code, transferable))
                                    }
      
}


module.exports = {Salter }