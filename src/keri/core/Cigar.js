const { Matter } = require('./matter');

/**
 * @description Cigar is Matter subclass holding a nonindexed signature with verfer property.
        From Matter .raw is signature and .code is signature cipher suite
    Adds .verfer property to hold Verfer instance of associated verifier public key
        Verfer's .raw as verifier key and .code is verifier cipher suite.
 */
class Cigar extends Matter {


    constructor(verfer = null, ...kwa){
        console.log("Value of ...kwa",...kwa)
        super(...kwa)
        this._verfer = verfer
    }


    /**
     *@description  Property verfer:
        Returns Verfer instance
        Assumes ._verfer is correctly assigned
     */
    verfer(){
        return this._verfer
    }


    setVerfer(verfer){
        this._verfer = verfer
    }
}


module.exports = {Cigar}