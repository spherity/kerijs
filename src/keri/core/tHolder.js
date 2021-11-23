/**
 *    """
    Tholder is KERI Signing Threshold Satisfactionclass
    .satisfy method evaluates satisfaction based on ordered list of indices of
    verified signatures where indices correspond to offsets in key list of
    associated signatures.

    Has the following public properties:

    Properties:
        .sith is original signing threshold
        .thold is parsed signing threshold
        .limen is the extracted string for the next commitment to the threshold
        .weighted is Boolean True if fractional weighted threshold False if numeric
        .size is int of minimun size of keys list

    Hidden:
        ._sith is original signing threshold
        ._thold is parsed signing threshold
        ._limen is extracted string for the next commitment to threshold
        ._weighted is Boolean, True if fractional weighted threshold False if numeric
        ._size is int minimum size of of keys list
        ._satisfy is method reference of threshold specified verification method
        ._satisfy_numeric is numeric threshold verification method
        ._satisfy_weighted is fractional weighted threshold verification method

 */

const { string2Bin } = require('../help/stringToBinary');

class Tholder {
  /**
     *
     * @param {*} sith   sith is either hex string of threshold number or iterable of fractional
                weights. Fractional weights may be either an iterable of
                fraction strings or an iterable of iterables of fractions strings.

                The verify method appropriately evaluates each of the threshold
                forms.

     */
  constructor(sith = '') {
    this.sith = sith;
    if (sith instanceof String) {
      this.weighted = false;
      const thold = parseInt(sith, 16);
      if (thold < 1) {
        throw new Error(`Invalid sith = ${thold} < 1.`);
      }
      this.thold = thold;
      this.size = this.thold; // used to verify that keys list size is at least size
      this.satisfy = this.satisfy_numeric;
      this.limen = this.sith; // just use hex string
    } else {
      this.weighted = true;
      if (!sith) {
        throw new Error(`Invalid sith = ${sith}, empty weight list.`);
      }
    }
  }

  setSith() {
    return this.sith();
  }

  getThold() {
    return this.thold();
  }

  getWeighted() {
    return this.weighted();
  }

  getSize() {
    return this.size();
  }

  getLimen() {
    return this.limen();
  }

  satisfy() {

  }

  /**
     * @description Returns True if satisfies numeric threshold False otherwise
     * @param {*} indices indices is list of indices (offsets into key list) of verified signatures
     */
  satisfyNumeric(indices) {
    try {
      if (indices.length >= this.thold()) {
        return true;
      }
    } catch (ex) {
      return false;
    }
    return false;
  }
}

module.exports = { Tholder };
