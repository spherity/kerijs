

const { allCharcodes , Codes } = require('./derivationCode&Length');
const {Matter} = require('./matter')


/**
 *  """
    Dater is subclass of Matter, cryptographic material, for ISO-8601 datetimes.
    Dater provides a custom Base64 coding of an ASCII ISO-8601 datetime by replacing
    the three non-Base64 characters ':.+' with the Base64 equivalents 'cdp'.
    Dater provides a more compact representation than would be obtained by converting
    the raw ASCII ISO-8601 datetime to Base64.
    Dater supports datetimes as attached crypto material in replay of events for
    the datetime of when the event was first seen.
    Restricted to specific 32 byte variant of ISO-8601 date time with microseconds
    and UTC offset in HH:MM. For example:

    '2020-08-22T17:50:09.988921+00:00'
    '2020-08-22T17:50:09.988921-01:00'

    The fully encoded versions are respectively

    '1AAG2020-08-22T17c50c09d988921p00c00'
    '1AAG2020-08-22T17c50c09d988921-01c00'

    Useful when parsing attached first seen couples with fn  + dt

    Uses default initialization code = MtrDex.DateTime
    Raises error on init if code not  MtrDex.DateTime

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
        .dts is the ISO-8601 datetime string

 */
class Dater extends Matter {

    /**
     * 
  """
        Inhereited Parameters:  (see Matter)
            raw is bytes of unqualified crypto material usable for crypto operations
            qb64b is bytes of fully qualified crypto material
            qb64 is str or bytes  of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            code is str of derivation code
            index is int of count of attached receipts for CryCntDex codes

        Parameters:
            dt the ISO-8601 datetime as str or bytes
        """
     */
    constructor(raw=null, qb64b=null, qb64=null, qb2=null,
        code=allCharcodes.SALT_128, dts=null, ...kwa){
            
            
            if((raw == null) &&  (qb64b == null) &&  (qb64 == null)  &&  (qb2 == null)){
                
                if(dts == null){
                    var date = new Date();
                    dts = date.toISOString(); //"2011-12-19T15:28:46.493Z"
                }
                console.log("Value of dts: ",dts.length)
                if( dts.length != 32){  
                throw new Error(`Invalid length of date time string`)
                }
                if (dts.hasAttribute("decode")){
                    dts = dts.toString("utf-8")
                }
                qb64 = allCharcodes.DateTime + dts.replace(":.+", "cdp")
            }

            super(raw,code, qb64b, qb64, qb2, ...kwa);

            if(this.code() != allCharcodes.DateTime){
                throw new Error(`Invalid code = ${this.code()} for Dater date time.`)
            }
    }

    /**
     * Returns .raw converted to int
     */
    dts(){

        return (this.qb64()).slice([Codes[this.code()].hs,(this.qb64()).length]).replace(("cdp", ":.+"))
    }
}

module.exports = {Dater}