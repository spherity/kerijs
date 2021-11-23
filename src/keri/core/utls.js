/* eslint-disable no-bitwise */

const utf8 = require('utf8');
var bignum = require('bignum');
const { intToB64, intToB64ForBigInt } = require('../help/stringToBinary');

function pad(n, width = 3, z = 0) {
  return (String(z).repeat(width) + String(n)).slice(String(n).length);
}

/**
 * @description  Returns list of depth first recursively extracted values from elements of
    key event dict ked whose flabels are in lables list

 * @param {*} ked  ked is key event dict
 * @param {*} labels    labels is list of element labels in ked from which to extract values
 */
function extractValues(ked, labels) {
  let values = [];
  for (let label of labels) {
    values = extractElementValues(ked[label], values);
  }

  return values;
}




/**
 * @description   Recusive depth first search that recursively extracts value(s) from element
    and appends to values list
    Assumes that extracted values are str

 * @param {*} element
 * @param {*} values
 */

function extractElementValues(element, values) {
  let data = [];


  try {
    if ((element instanceof Array) && !(typeof(element) == 'string')) {
      for (let k in element)
        extractElementValues(element[k], values);
    } else if (typeof(element) == 'string') {
      values.push(element);
    }
    data = values;
  } catch (error) {
    throw new Error(error);
  }

  return data;
}




/**
 * @description Returns True if obj is non-string iterable, False otherwise

 * @param {*} obj
 */



/**
 * @description  Javascript version of python range()
 * @param {*} start // Starting point
 * @param {*} stop  // ending point
 * @param {*} step
 */

function range(start, stop, step) {
  if (typeof stop == 'undefined') {
    // one param defined
    stop = start;
    start = 0;
  }

  if (typeof step == 'undefined') {
    step = 1;
  }

  if ((step > 0 && start >= stop) || (step < 0 && start <= stop)) {
    return [];
  }

  let result = [];
  for (let i = start; step > 0 ? i < stop : i > stop; i += step) {
    result.push(i);
  }

  return result;
}


/**
 * @description Returns integer value that is symmetric ceiling of r away from zero
    Symmetric ceiling function
    Because int() provides a symmetric floor towards zero, just inc int(r) by:
     1 when r - int(r) >  0  (r positive)
    -1 when r - int(r) <  0  (r negative)
     0 when r - int(r) == 0  (r integral already)
    abs(r) > abs(int(r) or 0 when abs(r)
 * @param {} r
 */
function sceil(r) {
  return (parseInt(r) + isign((r - parseInt(r))));
}

/**
 * @description     Return first l sextets from front (left) of b as bytes (byte string).
    Length of bytes returned is minimum sufficient to hold all l sextets.
    Last byte returned is right bit padded with zeros
 * @param {*} b bytes or str
 * @param {*} l sextets
 */

function nabSextets(b, l) {
  if (b) {
    // utf8.encode(b);
  }
  const n = sceil(l * (3 / 4)); //  number of bytes needed for l sextets
  if (n > b.length) {
    throw new Error(`Not enough bytes in ${b} to nab ${l} sextets.`);
  }
  const buf = b.slice(0, n);
  
  let i = bignum.fromBuffer(buf)
  let intNum1 = BigInt(i.toString())
  //buf.readUInt32BE(0);
  const p = BigInt(2 * (l % 4));
  // eslint-disable-next-line no-bitwise
  intNum1 >>= p; //  strip of last bits
  intNum1 <<= p; //  pad with empty bits
  //   return (i.to_bytes(n, 'big'))
  return bignum.toBuffer(intNum1);
}

/**
 *     Returns 1 if i > 0, -1 if i < 0, 0 otherwise
    Integer sign function
 */
function isign(i) {
  if (i > 0) {
    return 1;
  } if (i < 0) {
    return -1;
  }
  return 0;
}

/**
 * @description Returns conversion (encode) of l Base2 sextets from front of b to Base64 chars.
    One char for each of l sextets from front (left) of b.
    This is useful for encoding as code characters, sextets from the front of
    a Base2 bytes (byte string). Must provide l because of ambiguity between l=3
    and l=4. Both require 3 bytes in b.
 * @param {} b 
 * @param {*} l 
 */
function b2ToB64BigInt(b, l) {
  if (b) {
    // b = utf8.encode(b);
  }
  const n = sceil(l * (3 / 4)); //  number of bytes needed for l sextets
  if (n > b.length) {
    throw new Error(`Not enough bytes in ${b} to nab ${l} sextets.`);
  }

  const buf = b.slice(0, n);
  let i =bignum.fromBuffer(buf) 
 i =  BigInt(i.toString())

 let intNum2 = BigInt((2 * (l % 4)))
  i >>= intNum2;//  shift out padding bits make right aligned
  return (intToB64ForBigInt(i, l));
}



/**
 * @description Returns conversion (encode) of l Base2 sextets from front of b to Base64 chars.
    One char for each of l sextets from front (left) of b.
    This is useful for encoding as code characters, sextets from the front of
    a Base2 bytes (byte string). Must provide l because of ambiguity between l=3
    and l=4. Both require 3 bytes in b.
 * @param {} b 
 * @param {*} l 
 */
    function b2ToB64(b, l) {
      if (b) {
        b = utf8.encode(b);
      }
      const n = sceil(l * (3 / 4)); //  number of bytes needed for l sextets
      if (n > b.length) {
        throw new Error(`Not enough bytes in ${b} to nab ${l} sextets.`);
      }
    
      const buf = b.slice(0, n.length);
      let i =bignum.fromBuffer(buf) 
     i =  BigInt(i.toString())
    
     let intNum2 = BigInt((2 * (l % 4)))
      i >>= intNum2;//  shift out padding bits make right aligned
      return (intToB64(i, l));
    }


function getShiftedString(s, leftShifts, rightShifts) {
  // using `split('')` will result in certain unicode characters being separated incorrectly
  // use Array.from instead:
   const arr = Array.from(s);
   const netLeftShifts = (leftShifts - rightShifts) % arr.length;
   return [...arr.slice(netLeftShifts), ...arr.slice(0, netLeftShifts)]
     .join('');
 }

 function leftShifting(s, leftShifts) {
  return s.substring(leftShifts) + s.substring(0, leftShifts);
}


function convertBase(str, fromBase, toBase) {

  const DIGITS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/";

  const add = (x, y, base) => {
      let z = [];
      const n = Math.max(x.length, y.length);
      let carry = 0;
      let i = 0;
      while (i < n || carry) {
          const xi = i < x.length ? x[i] : 0;
          const yi = i < y.length ? y[i] : 0;
          const zi = carry + xi + yi;
          z.push(zi % base);
          carry = Math.floor(zi / base);
          i++;
      }
      return z;
  }

  const multiplyByNumber = (num, x, base) => {
      if (num < 0) return null;
      if (num == 0) return [];

      let result = [];
      let power = x;
      while (true) {
          num & 1 && (result = add(result, power, base));
          num = num >> 1;
          if (num === 0) break;
          power = add(power, power, base);
      }

      return result;
  }

  const parseToDigitsArray = (str, base) => {
      const digits = str.split('');
      let arr = [];
      for (let i = digits.length - 1; i >= 0; i--) {
          const n = DIGITS.indexOf(digits[i])
          if (n == -1) return null;
          arr.push(n);
      }
      return arr;
  }

  const digits = parseToDigitsArray(str, fromBase);
  if (digits === null) return null;

  let outArray = [];
  let power = [1];
  for (let i = 0; i < digits.length; i++) {
      digits[i] && (outArray = add(outArray, multiplyByNumber(digits[i], power, toBase), toBase));
      power = multiplyByNumber(fromBase, power, toBase);
  }

  let out = '';
  for (let i = outArray.length - 1; i >= 0; i--)
      out += DIGITS[outArray[i]];

  return out;
}


const Bizes = 
{ '\x00' : 1 , '\x04' : 1, 
 '\x08': 1, '\x0c' : 1,
  '\x10': 1, '\x14': 1,
  '\x18': 1,'\x1c': 1,
  ' ': 1,'$': 1,
  '(': 1,',': 1,'0': 1,'4': 1,
  '8': 1,
  '<': 1,
  '@': 1,
  'D': 1,
  'H': 1,
  'L': 1,
  'P': 1,
  'T': 1,
  'X': 1,
  '\\': 1,
  '`': 1,
  'd': 1,
  'h': 1,
  'l': 1,
  'p': 1,
  't': 1,
  'x': 1, '|': 1, '\x80': 1, '\x84': 1, '\x88': 1, '\x8c': 1, '\x90': 1, '\x94': 1, '\x98': 1, '\x9c': 1, '\xa0': 1, '\xa4': 1, '\xa8': 1,
   '\xac': 1, '\xb0': 1, '\xb4': 1, '\xb8': 1, '\xbc': 1, '\xc0': 1, '\xc4': 1, '\xc8': 1, '\xcc': 1, '\xd0': 2, '\xd4': 4, '\xd8': 5,
    '\xdc': 6, '\xe0': 8, '\xe4': 9, '\xe8': 10 }

  const Tierage = {
    low:'low', med:'med', high:'high'
  }
module.exports = {
  pad, extractValues, range, nabSextets, sceil, b2ToB64, getShiftedString, leftShifting, Bizes, b2ToB64BigInt, Tierage
};
