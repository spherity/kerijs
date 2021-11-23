const util = require('./utls');

const VERRAWSIZE = 6;
const Versionage = { major: 1, minor: 0 };
const Serialage = { json: '', mgpk: '', cbor: '' };
const Vstrings = Serialage;
const Serials = { json: 'JSON', mgpk: 'MGPK', cbor: 'CBOR' };

// # element labels to exclude in digest or signature derivation from inception icp
const IcpExcludes = ['pre'];
// # element labels to exclude in digest or signature derivation from delegated inception dip
const DipExcludes = ['pre'];
const Ilks = {
  icp: 'icp',
  rot: 'rot',
  ixn: 'ixn',
  dip: 'dip',
  drt: 'drt',
  rct: 'rct',
  vrc: 'vrc',
};

const IcpLabels = [
  'vs',
  'pre',
  'sn',
  'ilk',
  'sith',
  'keys',
  'nxt',
  'toad',
  'wits',
  'cnfg',
];
const DipLabels = [
  'vs',
  'pre',
  'sn',
  'ilk',
  'dig',
  'sith',
  'keys',
  'nxt',
  'toad',
  'cuts',
  'adds',
  'perm',
  'seal',
];

// let mimes = {
//   json: "application/keri+json",
//   mgpk: "application/keri+msgpack",
//   cbor: "application/keri+cbor",
// };
// let yourNumber = 899
// let hexString =  yourNumber.toString(16);
// let two = '29'.toString(16);
// let three = '39'.toString(16)
// let VERFMT = `KERI${hexString} ${two} ${three}_`   /// version format string
const VERFULLSIZE = 17;
const MINSNIFFSIZE = 12 + VERFULLSIZE;
const MINSIGSIZE = 4;
/**
 * @description  It will return version string
 */
function versify(version = null, kind = Serials.json, size) {
  if (!(Object.values(Serials).indexOf(kind) > -1)) {
    throw new Error('Invalid serialization kind =', kind.toString(16));
  }

  if (!version) {
    version = Versionage;
  }

  const hex1 = version.major.toString(16);
  const hex2 = version.minor.toString(16);
  const kindHex = kind.toString(16);
  const hex3 = util.pad(size.toString(16), VERRAWSIZE);

  return `KERI${hex1}${hex2}${kindHex}${hex3}_`;
}

Vstrings.json = versify('', Serials.json, 0);
Vstrings.mgpk = versify('', Serials.mgpk, 0);
Vstrings.cbor = versify('', Serials.cbor, 0);

// const version_pattern = 'KERI(?P<major>[0-9a-f])(?P<minor>[0-9a-f])
// (?P<kind>[A-Z]{4})(?P<size>[0-9a-f]{6})'
// const version_pattern1 = `KERI\(\?P<major>\[0\-9a\-f\]\)\(\?P<minor>\[0\-9a\-f\]\)\
// (\?P<kind>\[A\-Z\]\{4\}\)\(\?P<size>\[0\-9a\-f\]\{6\}\)_`

const VEREX = 'KERI([0-9a-f])([0-9a-f])([A-Z]{4})([0-9a-f]{6})';

// Regex pattern matching

/**
 * @description This function is use to deversify the version
 * Here we will use regex to  to validate and extract serialization kind,size and version
 * @param {string} vs   version string
 * @return {Object}  contaning kind of serialization like cbor,json,mgpk
 *                    version = version of object ,size = raw size integer
 */
function deversify(versionString) {
  let kind;
  let size;
  const version = Versionage;

  // we need to identify how to match the buffers pattern ,like we do regex matching for strings
  const re = new RegExp(VEREX);

  const match = re.exec(versionString);

  if (match) {
    [version.major, version.minor, kind, size] = [
      match[1],
      match[2],
      match[3],
      match[4],
    ];
    if (!Object.values(Serials).includes(kind)) {
      throw new Error(`Invalid serialization kind = ${kind}`);
    }
    return [kind, version, size];
  }
  throw new Error(`Invalid version string = ${versionString}`);
}

module.exports = {
  deversify,
  versify,
  Versionage,
  Ilks,
  Serialage,
  Serials,
  IcpLabels,
  DipLabels,
  Vstrings,
  MINSNIFFSIZE,
  MINSIGSIZE,
  IcpExcludes,
  DipExcludes,
};
