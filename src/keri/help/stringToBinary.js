const Deque = require('collections/deque');
const derivationCodeLength = require('../core/derivationCode&Length');
function string2Bin(s) {
  var b = new Array();
  var last = s.length;

  for (var i = 0; i < last; i++) {
    var d = s.charCodeAt(i);
    if (d < 128)
      b[i] = dec2Bin(d);
    else {
      let c = s.charAt(i);
      b[i] = -1;
    }
  }
  return b;
}

function dec2Bin(d) {
  var b = '';

  for (var i = 0; i < 8; i++) {
    b = (d % 2) + b;
    d = Math.floor(d / 2);
  }

  return b;
}

function intToB64(i, l = 1) {
  const queue = [];
  queue.unshift(derivationCodeLength.b64ChrByIdx[i % 64]);
  i = Math.floor(i / 64);
  if (i > 0) {
    for (let k = 0; k <= i; k++) {
      queue.unshift(derivationCodeLength.b64ChrByIdx[i % 64]);
      i = Math.floor(i / 64);
    }
  }

  const {length} = queue;

  for (let j = 0; j < l - length; j++) {
    queue.unshift(derivationCodeLength.b64ChrByIdx[j % 64]);
  }
  return queue.join('');
}
/**
 * @description Returns conversion of Base64 str cs to int
 * @param {} cs
 */
function b64ToInt(cs) {
  let i = 0;

  const splitString = cs.split('');
  const reverseArray = splitString.reverse();

  for (const [index, element] of reverseArray.entries()) {
    const keyOfValue = Object.keys(derivationCodeLength.b64ChrByIdx).find(key => derivationCodeLength.b64ChrByIdx[key] === element);
    i += keyOfValue * 64 ** index;
  }

  return i;
}

function ToInteger(x) {
  x = Number(x);
  return x < 0 ? Math.ceil(x) : Math.floor(x);
}

function modulo(a, b) {
  return a - Math.floor(a/b)*b;
}
function ToUint32(x) {
  return modulo(ToInteger(x), Math.pow(2, 32));
}

function ToInt32(x) {
  var uint32 = ToUint32(x);
  if (uint32 >= Math.pow(2, 31)) {
      return uint32 - Math.pow(2, 32)
  } else {
      return uint32;
  }
}


function intToB64ForBigInt(i, l = 1) {
  const queue = [];
  queue.unshift(derivationCodeLength.b64ChrByIdx[i % BigInt(64)]); 
  i = i / BigInt(64)
  if (i > BigInt(0)) {
    for (let k = 0; k <= i; k++) {
      queue.unshift(derivationCodeLength.b64ChrByIdx[i % BigInt(64)]);
      i = i / BigInt(64)
    }
  }

  const {length} = queue;

  for (let j = 0; j < l - length; j++) {
    queue.unshift(derivationCodeLength.b64ChrByIdx[j % 64]);
  }
  return queue.join('');
}
module.exports = {
  string2Bin,
  intToB64,
  b64ToInt,
  ToInt32,
  intToB64ForBigInt,
};
