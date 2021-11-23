const libsodium = require('libsodium-wrappers-sumo');
const Base64 = require('urlsafe-base64');
const assert = require('assert').strict;
const blake3 = require('blake3');
var  { blake2b, createBLAKE2b, createBLAKE3, createBLAKE2s } = require('hash-wasm');
const { copySync } = require('fs-extra');
const crypto = require("crypto")
const msgpack = require('msgpack5')();
// const utf8 = require('utf8');
var bignum = require('bignum');
const cbor = require('cbor');
const { size, findLastKey } = require('lodash');
const utf8 = require('utf8');
const {derivationCodes,stringToBnary,Crymat, Matter, CryCounter, Verfer, Diger, Cigar,
   Prefixer, Nexter, Sigver, SigMat, Signer, Serder, Seqner, Dater, Salter, rawSize} = require('../../src/keri/core/index')
const {
  versify,
  Serials,
  Versionage,
  Ilks,
  Vstrings,
  Serialage,
} = require('../../src/keri/core/core');
// namespace our extensions
const { encode } = msgpack;
const { decode } = msgpack;

const VERFULLSIZE = 17;
const MINSNIFFSIZE = 12 + VERFULLSIZE;

async function test_cryderivationcodes() {
  assert.equal(derivationCodes.crySelectCodex.two, 0);
  const crySelectCodex = JSON.stringify(derivationCodes.crySelectCodex);

  assert.equal(derivationCodes.oneCharCode.Ed25519_Seed == 'A');
  assert.equal(derivationCodes.oneCharCode.Ed25519N == 'B');
  assert.equal(derivationCodes.oneCharCode.X25519 == 'C');
  assert.equal(derivationCodes.oneCharCode.Ed25519 === 'D');
  assert.equal(derivationCodes.oneCharCode.Blake3_256 == 'E');
  assert.equal(derivationCodes.oneCharCode.Blake2b_256 == 'F');
  assert.equal(derivationCodes.oneCharCode.Blake2s_256 == 'G');
  assert.equal(derivationCodes.oneCharCode.SHA3_256 == 'H');
  assert.equal(derivationCodes.oneCharCode.SHA2_256 == 'I');
  assert.equal(derivationCodes.oneCharCode.ECDSA_secp256k1_Seed == 'J');
  assert.equal(derivationCodes.oneCharCode.Ed448_Seed == 'K');
  assert.equal(derivationCodes.oneCharCode.X448 == 'L');

  const { oneCharCode } = derivationCodes;
  // oneCharCode.includes('0') == false;

  assert.equal(derivationCodes.twoCharCode.Seed_128 == '0A');
  assert.equal(derivationCodes.twoCharCode.Ed25519 == '0B');
  assert.equal(derivationCodes.twoCharCode.ECDSA_256k1 == '0C');

  const jsonString = JSON.stringify(derivationCodes.twoCharCode);
  jsonString.includes('A') === false;
}

/**
 * @description : Test the support functionality for cryptographic material
 * @status partially completed
 */
async function test_cryMat() {
  await libsodium.ready;
  const keypair = libsodium.crypto_sign_keypair();
  let verkey = 'iN\x89Gi\xe6\xc3&~\x8bG|%\x90(L\xd6G\xddB\xef`\x07\xd2T\xfc\xe1\xcd.\x9b\xe4#';
  let prebin = '\x05\xa5:%\x1d\xa7\x9b\x0c\x99\xfa-\x1d\xf0\x96@\xa13Y\x1fu\x0b\xbd\x80\x1fIS\xf3\x874\xbao\x90\x8c';

  verkey = Buffer.from(verkey, 'binary');
  const prefix = 'BaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM';
  prebin = Buffer.from(prebin, 'binary');

  let cryMat = new Crymat(verkey);
  const res_infil = cryMat.qb2();

  assert.deepStrictEqual(cryMat.raw(), verkey);
  assert.deepStrictEqual(cryMat.code(), derivationCodes.oneCharCode.Ed25519N);
  assert.deepStrictEqual(cryMat.qb64(), prefix);
  // assert.deepStrictEqual(res_infil, prebin.toString());

  // assert.deepStrictEqual(cryMat.code(), derivationCodes.oneCharCode.Ed25519N);
  // assert.deepStrictEqual(cryMat.raw(), verkey);

  // assert.deepStrictEqual(cryMat.code(), derivationCodes.oneCharCode.Ed25519N);
  // assert.deepStrictEqual(cryMat.raw(), verkey);

  // cryMat = new Crymat(
  //   null,
  //   prefix,
  //   null,
  //   derivationCodes.oneCharCode.Ed25519N,
  //   0,
  // );
  // assert.deepStrictEqual(cryMat.code(), derivationCodes.oneCharCode.Ed25519N);
  // assert.deepStrictEqual(cryMat.raw(), verkey);



  // cryMat = new Crymat(
  //   null,
  //   null,
  //   prebin,
  //   derivationCodes.oneCharCode.Ed25519N,
  //   0,
  // );
  // assert.deepStrictEqual(cryMat.code(), derivationCodes.oneCharCode.Ed25519N);
  // assert.deepStrictEqual(cryMat.raw(), verkey);

  // cryMat = new Crymat(
  //   null,
  //   Buffer.from(prefix, 'utf-8'),
  //   null,
  //   derivationCodes.oneCharCode.Ed25519N,
  //   0,
  // ); // test auto convert bytes to str
  // assert.deepStrictEqual(cryMat.code(), derivationCodes.oneCharCode.Ed25519N);
  // assert.deepStrictEqual(cryMat.raw(), verkey);
  // assert.deepStrictEqual(cryMat.qb64(), prefix);
  // assert.deepStrictEqual(cryMat.qb64b().toString(), prefix);

  // const full = `${prefix}:mystuff/mypath/toresource?query=what#fragment`;
  // cryMat = new Crymat(null, Buffer.from(full, 'utf-8'));
  // assert.deepStrictEqual(cryMat.code(), derivationCodes.oneCharCode.Ed25519N);
  // assert.deepStrictEqual(cryMat.raw(), verkey);
  // assert.deepStrictEqual(cryMat.qb64(), prefix);

  // assert.deepStrictEqual(cryMat.qb2(), prebin.toString());

  // // ----------------- Signature tests   Need to fix--------------------------------------

  // let sig = "\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp\x0e'm\x8f@\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)\xde\xca\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o\"\x81&\t";

  // sig = Buffer.from(sig, 'binary');
  // const sig64 = Base64.encode(sig);
  // assert.deepStrictEqual(
  //   sig64,
  //   'mdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ',
  // );

  // //      ===============================================
  // const qsig64 = '0BmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ';
  // let qbin = '\xd0\x19\x9d#\xc3\x92BC\t\xf6\xbf\xb1\x8a\x08\xc4\x07!#"\xe6\xbb,q\xf7\x00\xe2v\xd8\xf4\n\xaaX\xcc\x86\xe8\\\x82\x1fg\x19\x17\n\x9e\xcc\xf9*\xf2\x9d\xec\xaf\xc7\xf7\xedv\xf7\xc1x!\xddC\xc6\xf2(\x12`\x90';
  // qbin = Buffer.from(qbin, 'binary');
  // cryMat = new Crymat(
  //   sig,
  //   null,
  //   null,
  //   derivationCodes.twoCharCode.Ed25519,
  //   0,
  // );
  // assert.deepStrictEqual(cryMat.raw(), sig);
  // assert.deepStrictEqual(cryMat.code(), derivationCodes.twoCharCode.Ed25519);
  // assert.deepStrictEqual(cryMat.qb64(), qsig64);
  // assert.deepStrictEqual(cryMat.qb2(), decodeURIComponent(qbin));

  // cryMat = new Crymat(
  //   null,
  //   qsig64,
  //   null,
  //   derivationCodes.oneCharCode.Ed25519N,
  //   0,
  // );

  // assert.deepStrictEqual(cryMat.raw(), sig);
  // assert.deepStrictEqual(cryMat.code(), derivationCodes.twoCharCode.Ed25519);

  // cryMat = new Crymat(
  //   null,
  //   null,
  //   qbin,
  //   derivationCodes.twoCharCode.Ed25519,
  //   0,
  // );
  // assert.deepStrictEqual(cryMat.raw(), sig);
  // assert.deepStrictEqual(cryMat.code(), derivationCodes.twoCharCode.Ed25519);
}

/**

/**
 * @description Subclass of crymat
 * @status Pending , need to resolve issue
 */
async function test_crycounter() {
  let qsc = derivationCodes.CryCntCodex.Base64 + stringToBnary.intToB64(1, (l = 2));
  assert.equal(qsc, '-AAB');

  const qscb = encodeURIComponent(qsc);
  let counter = new CryCounter();

  assert.deepStrictEqual(counter.raw(), Buffer.from('', 'binary'));
  assert.deepStrictEqual(counter.code(), derivationCodes.CryCntCodex.Base64);
  assert.deepStrictEqual(counter.index(), 1);
  assert.deepStrictEqual(counter.count(), 1);
  assert.deepStrictEqual(counter.qb64(), qsc);
  console.log('typeof(counter.qb2()) ===================>', counter.qb2().toString('utf-8'));
  // assert.deepStrictEqual(
  //   Buffer.from(counter.qb2(), "binary").toString(),
  //   "-AAB"
  // );

  counter = new CryCounter(Buffer.from('', 'binary'));
  assert.deepStrictEqual(counter.raw(), Buffer.from('', 'binary'));
  assert.deepStrictEqual(counter.code(), derivationCodes.CryCntCodex.Base64);
  assert.deepStrictEqual(counter.index(), 1);
  assert.deepStrictEqual(counter.count(), 1);
  assert.deepStrictEqual(counter.qb64(), qsc);
  // assert.deepStrictEqual(counter.qb2(), "-AAB");

  counter = new CryCounter(null, null, qsc, null);
  assert.deepStrictEqual(counter.raw(), Buffer.from('', 'binary'));
  assert.deepStrictEqual(counter.code(), derivationCodes.CryCntCodex.Base64);
  assert.deepStrictEqual(counter.index(), 1);
  assert.deepStrictEqual(counter.count(), 1);
  assert.deepStrictEqual(counter.qb64(), qsc);
  // assert.deepStrictEqual(
  //   Buffer.from(counter.qb2(), "binary").toString(),
  //   "-AAB"
  // );

  counter = new CryCounter(null, null, qscb, null);
  assert.deepStrictEqual(counter.raw(), Buffer.from('', 'binary'));
  assert.deepStrictEqual(counter.code(), derivationCodes.CryCntCodex.Base64);
  assert.deepStrictEqual(counter.index(), 1);
  assert.deepStrictEqual(counter.count(), 1);
  assert.deepStrictEqual(counter.qb64(), qsc);
  // assert.deepStrictEqual(
  //   Buffer.from(counter.qb2(), "binary").toString(),
  //   "-AAB"
  // );

  counter = new CryCounter(
    Buffer.from('', 'binary'),
    null,
    null,
    null,
    derivationCodes.CryCntCodex.Base64,
    null,
    1,
  );
  assert.deepStrictEqual(counter.raw(), Buffer.from('', 'binary'));
  assert.deepStrictEqual(counter.code(), derivationCodes.CryCntCodex.Base64);
  assert.deepStrictEqual(counter.index(), 1);
  assert.deepStrictEqual(counter.count(), 1);
  assert.deepStrictEqual(counter.qb64(), qsc);
  // assert.deepStrictEqual(
  //   Buffer.from(counter._qb2(), "binary").toString(),
  //   "-AAB"
  // );

  counter = new CryCounter(
    Buffer.from('', 'binary'),
    null,
    null,
    null,
    derivationCodes.CryCntCodex.Base64,
    null,
    0,
  );
  assert.deepStrictEqual(counter.raw(), Buffer.from('', 'binary'));
  assert.deepStrictEqual(counter.code(), derivationCodes.CryCntCodex.Base64);
  assert.deepStrictEqual(counter.index(), 0);
  assert.deepStrictEqual(counter.count(), 0);
  assert.deepStrictEqual(counter.qb64(), '-AAA');
  // assert.deepStrictEqual(
  //   Buffer.from(counter._qb2(), "binary").toString(),
  //   "-AAB"
  // );

  const cnt = 5;
  qsc = derivationCodes.CryCntCodex.Base64 + stringToBnary.intToB64(cnt, (l = 2));

  counter = new CryCounter(
    null,
    null,
    null,
    null,
    derivationCodes.CryCntCodex.Base64,
    null,
    cnt,
  );
  assert.equal(qsc, '-AAF');
  assert.deepStrictEqual(counter.raw(), Buffer.from('', 'binary'));
  assert.deepStrictEqual(counter.code(), derivationCodes.CryCntCodex.Base64);
  assert.deepStrictEqual(counter.index(), cnt);
  assert.deepStrictEqual(counter.count(), cnt);
  assert.deepStrictEqual(counter.qb64(), qsc);
  // assert.deepStrictEqual(
  //   Buffer.from(counter._qb2(), "binary").toString(),
  //   "-AAB"
  // );

  counter = new CryCounter(null, null, qsc, null);
  // assert.equal(qsc, '-AAF')
  assert.deepStrictEqual(counter.raw(), Buffer.from('', 'binary'));
  assert.deepStrictEqual(counter.code(), derivationCodes.CryCntCodex.Base64);
  assert.deepStrictEqual(counter.index(), cnt);
  assert.deepStrictEqual(counter.count(), cnt);
  assert.deepStrictEqual(counter.qb64(), qsc);
  // assert.deepStrictEqual(
  //   Buffer.from(counter._qb2(), "binary").toString(),
  //   "-AAB"
  // );

  qsc = derivationCodes.CryCntCodex.Base2 + stringToBnary.intToB64(cnt, (l = 2));

  counter = new CryCounter(
    null,
    null,
    null,
    null,
    derivationCodes.CryCntCodex.Base2,
    null,
    cnt,
  );
  assert.equal(qsc, '-BAF');
  assert.deepStrictEqual(counter.raw(), Buffer.from('', 'binary'));
  assert.deepStrictEqual(counter.code(), derivationCodes.CryCntCodex.Base2);
  assert.deepStrictEqual(counter.index(), cnt);
  assert.deepStrictEqual(counter.count(), cnt);
  assert.deepStrictEqual(counter.qb64(), qsc);
  // assert.deepStrictEqual((Buffer.from(counter._qb2() ,'binary')).toString() ,'-AAB')

  counter = new CryCounter(null, null, qsc, null);
  // assert.equal(qsc, '-AAF')
  assert.deepStrictEqual(counter.raw(), Buffer.from('', 'binary'));
  assert.deepStrictEqual(counter.code(), derivationCodes.CryCntCodex.Base2);
  assert.deepStrictEqual(counter.index(), cnt);
  assert.deepStrictEqual(counter.count(), cnt);
  assert.deepStrictEqual(counter.qb64(), qsc);
  // assert.deepStrictEqual((Buffer.from(counter._qb2() ,'binary')).toString() ,'-AAB')
}

/**
 * @status completed
 */
async function test_diger() {
  // Create something to digest and verify
  let ser = 'abcdefghijklmnopqrstuvwxyz0123456789'
  //Buffer.from('abcdefghijklmnopqrstuvwxyz0123456789', 'binary');
  let hasher =   await  createBLAKE3(128);    
  hasher = hasher.init();     //blake3.createHash();          //blake3.hash(ser);
  let digest = hasher.update(ser).digest();
 let blakeInstance = await Diger.initBlake();
 console.log("Value of blake instance is = ",digest.length)
  //  let diger = new Diger(Buffer.from(digest, 'binary'), null , derivationCodes.oneCharCode.Blake3_256, blakeInstance);    // digest
  // assert.deepStrictEqual(diger.code(), derivationCodes.oneCharCode.Blake3_256);
  // assert.deepStrictEqual(
  //   diger.raw().length,
  //   derivationCodes.CryOneRawSizes[diger.code()],
  // );
  // let result = diger.verify(ser);
  // assert.equal(result, true);
  // result = diger.verify(
  //   Buffer.concat([Buffer.from(ser, 'binary'), Buffer.from('2j2idjpwjfepjtgi', 'binary')])
  // );
  // assert.equal(result, false);
  // diger = new Diger(Buffer.from(digest, 'binary'), null, derivationCodes.oneCharCode.Blake3_256, blakeInstance);
  // assert.deepStrictEqual(diger.code(), derivationCodes.oneCharCode.Blake3_256);
  // assert.deepStrictEqual(
  //   diger.raw().length,
  //   derivationCodes.CryOneRawSizes[diger.getCode],
  // );
  // result = diger.verify(ser);
  // assert.equal(result, true);

  // diger = new Diger(null, ser, derivationCodes.oneCharCode.Blake3_256, blakeInstance);
  // assert.deepStrictEqual(diger.code(), derivationCodes.oneCharCode.Blake3_256);
  // assert.deepStrictEqual(
  //   diger.raw().length,
  //   derivationCodes.CryOneRawSizes[diger.code()],
  // );
  // result = diger.verify(ser);
  // assert.deepStrictEqual((diger.qb64b()) , Buffer.from('EYjBiOTJmNzg4MTU0M2VmYjc3ZjMxODZkODE4NjA5NDQ','binary'));
  // let digb =  Buffer.from('EsLkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E','binary');
  //  dig =  'EsLkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E'
  // let kwa = [digb]
  // diger = new  Diger(null, null , derivationCodes.oneCharCode.Blake3_256 ,blakeInstance, ...kwa);
  // assert.deepStrictEqual(diger.qb64b(), digb)
  // assert.deepStrictEqual(diger.qb64() , dig);
  // assert.deepStrictEqual(diger.code() , derivationCodes.oneCharCode.Blake3_256);
  // kwa = [null, digb]
  // diger = new  Diger(null, null , derivationCodes.oneCharCode.Blake3_256 ,blakeInstance,  ...kwa);
  // assert.deepStrictEqual(diger.qb64(), dig);
  // assert.deepStrictEqual(diger.qb64b(), digb);
  // assert.deepStrictEqual(diger.code(), derivationCodes.oneCharCode.Blake3_256);


   let pig = Buffer.from('sLkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E=', 'binary');
    let raw = pig.toString();
  //   assert.deepStrictEqual(pig, Buffer.from(raw, 'binary'));



//     let hasher2b =   await createBLAKE2b(128);
//     hasher2b = hasher2b.init();

//   dig = hasher2b.update(ser).digest()
//   diger =  new Diger(Buffer.from( dig,'binary'),null , derivationCodes.oneCharCode.Blake2b_256, blakeInstance)
//   assert.deepStrictEqual(diger.code() , derivationCodes.oneCharCode.Blake2b_256)
//   assert.deepStrictEqual((diger.raw()).length , rawSize(diger.code()));
//   assert.deepStrictEqual(diger.verify(ser), true);


//   diger =  new Diger(null, ser , derivationCodes.oneCharCode.Blake2b_256, blakeInstance)

//   assert.deepStrictEqual(diger.code() , derivationCodes.oneCharCode.Blake2b_256)
//   assert.deepStrictEqual((diger.raw()).length , rawSize(diger.code()));
//   assert.deepStrictEqual(diger.verify(ser), true);


//   hasher2s = blakeInstance.blake2s.init();

// dig = hasher2s.update(ser).digest()

// console.log("Value of DIG = ==========>",dig , '    ', dig1);
// diger =  new Diger(Buffer.from( dig,'binary'),null , derivationCodes.oneCharCode.Blake2s_256, blakeInstance)
// assert.deepStrictEqual(diger.code() , derivationCodes.oneCharCode.Blake2s_256)
// assert.deepStrictEqual((diger.raw()).length , rawSize(diger.code()));
// assert.deepStrictEqual(diger.verify(ser), true);


// diger =  new Diger(null, ser , derivationCodes.oneCharCode.Blake2s_256, blakeInstance)
// assert.deepStrictEqual(diger.code() , derivationCodes.oneCharCode.Blake2s_256)
// assert.deepStrictEqual((diger.raw()).length , rawSize(diger.code()));
// assert.deepStrictEqual(diger.verify(ser), true);



dig = crypto.createHash("sha3-256").update(ser).digest()
console.log("DIG before slicing ====>",(dig).length)
 // dig = hashlib.sha3_256(ser).digest()
 //dig = dig.slice(0,32)

//   diger =  new Diger(Buffer.from( dig,'binary'), null , derivationCodes.oneCharCode.SHA3_256)
//   console.log("diger ==================>",dig)
//   assert.deepStrictEqual(diger.code() , derivationCodes.oneCharCode.SHA3_256)
// assert.deepStrictEqual((diger.raw()).length , rawSize(diger.code()));
// assert.deepStrictEqual(diger.verify(ser), true);



diger =  new Diger(null, ser , derivationCodes.oneCharCode.SHA3_256)
assert.deepStrictEqual(diger.code() , derivationCodes.oneCharCode.SHA3_256)
assert.deepStrictEqual((diger.raw()).length , rawSize(diger.code()));
assert.deepStrictEqual(diger.verify(ser), true);


dig = crypto.createHash("sha256").update(ser).digest()
  // dig = hashlib.sha256(ser).digest()

  diger =  new Diger(Buffer.from( dig,'binary'), null , derivationCodes.oneCharCode.SHA2_256)
assert.deepStrictEqual(diger.code() , derivationCodes.oneCharCode.SHA2_256)
assert.deepStrictEqual((diger.raw()).length , rawSize(diger.code()));
assert.deepStrictEqual(diger.verify(ser), true);

diger =  new Diger(null, ser , derivationCodes.oneCharCode.SHA2_256)
assert.deepStrictEqual(diger.code() , derivationCodes.oneCharCode.SHA2_256)
assert.deepStrictEqual((diger.raw()).length , rawSize(diger.code()));
assert.deepStrictEqual(diger.verify(ser), true);



  ser = Buffer.from('abcdefghijklmnopqrstuvwxyz0123456789', 'binary')

  let diger0 =  new Diger(null, ser, derivationCodes.oneCharCode.Blake3_256, blakeInstance )
  // diger0 = Diger(ser=ser) # default code
  let diger1 =  new Diger(null, ser, derivationCodes.oneCharCode.SHA3_256 , blakeInstance)
  let diger2 =  new Diger(null, ser, derivationCodes.oneCharCode.Blake2b_256, blakeInstance )
  // diger1 = Diger(ser=ser, code=MtrDex.SHA3_256)
  // diger2 = Diger(ser=ser, code=MtrDex.Blake2b_256)
  // diger0.compare(ser , null, diger1);
  // diger0.compare(ser , null, diger2);
  // diger1.compare(ser , null, diger2);

  diger0.compare(ser , diger1.qb64());
  diger0.compare(ser , diger2.qb64b());
  diger1.compare(ser , diger2.qb64());


  // ser1 = b'ABCDEFGHIJKLMNOPQSTUVWXYXZabcdefghijklmnopqrstuvwxyz0123456789'

  // assert not diger0.compare(ser=ser, diger=Diger(ser=ser1))  # codes match
  // assert not diger0.compare(ser=ser, dig=Diger(ser=ser1).qb64)  # codes match
  // assert not diger0.compare(ser=ser,  # codes not match
  //                           diger=Diger(ser=ser1, code=MtrDex.SHA3_256))
  // assert not diger0.compare(ser=ser,  # codes not match
  //                           dig=Diger(ser=ser1, code=MtrDex.SHA3_256).qb64b)

}

/**
 * @status pending
 */
async function test_nexter() {
  // let verkey = '\xacr\xda\xc83~\x99r\xaf\xeb`\xc0\x8cR\xd7\xd7\xf69\xc8E\x1e\xd2\xf0=`\xf7\xbf\x8a\x18\x8a`q';
  // verkey = Buffer.from(verkey, 'binary');
  // const verfer = new Verfer(verkey);

  // assert.deepStrictEqual(
  //   verfer.qb64(),
  //   'BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE',
  // );


  const sith = '2'.toString(16); // let hexString =  yourNumber.toString(16);
  let hasher =   await  createBLAKE3(128);    
  hasher = hasher.init();     //blake3.createHash();          //blake3.hash(ser);
  const sithDig =  hasher.update(Buffer.from(sith, 'binary')).digest();
  //  assert.deepStrictEqual(Buffer.from(sithDig, 'binary'), Buffer.from(`\x81>\x9br\x91A\xe7\xf3\x85\xaf\xa0\xa2\xd0\xdf>l7\x89\xe4'\xff\xe4\xae\xefVjV[\xc8\xf2\xfe=`, 'binary'))
 
  let blakeInstance = await Diger.initBlake();
  let sithdiger = new  Diger(Buffer.from(sithDig, 'binary'), null, derivationCodes.oneCharCode.Blake3_256, blakeInstance)
  assert.deepStrictEqual(sithdiger.qb64() , 'EODEzZTliNzI5MTQxZTdmMzg1YWZhMGEyZDBkZjNlNmM');

 let keys = ['BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE',
            'BujP_71bmWFVcvFmkE9uS8BTZ54GIstZ20nj_UloF8Rk',
            'B8T4xkb8En6o0Uo5ZImco1_08gT5zcYnXzizUPVNzicw']

         //  let hash =  blakeInstance.blake3.init();
          // console.log("Value of Hash = ",hash)
           let keydigs = []
            for(let key in keys){    
              let hash =  blakeInstance.blake3.init()
              keydigs.push(Buffer.from(hash.update(keys[key]).digest('binary')));
            }
            
            const key1 = Buffer.from(`\x98\x1d\xba\xc8\xcc\xeb\xa0\x80\xa1\xfa\x8aJ5\xd9\x18\xc8\xfd4\xd2L\x1e\xbdM|Y\x02=\xe4\x96\x89\x0e6`,'binary');
            const key2 = Buffer.from(';\x80\x97\xa7\xc8,\xd3"`\xd5\xf1a$\xbb9\x84~\xa7z\xa2p\x84Q\x18\xee\xfa\xc9\x11\xd3\xde\xf3\xb2','binary');
            const key3 = Buffer.from('-e\x99\x13 i\x8e\xb7\xcc\xd5E4\x9f}J#"\x17\x96Z\xc2\xa0\xb1\x0e#\x95\x07\x0f\xdc{[\x12','binary');
            let keysArray = [key1,key2,key3];
           
     assert.deepStrictEqual(keydigs,keysArray)
        //       let digers = []
        // for(let keydig in keydigs){
        //   let hash =  blakeInstance.blake3.init()
        //   digers.push(Buffer.from(hash.update(keydigs[keydig]).digest('binary')));
        // }

        let digs = []
        let digers = []
        for(let keydig in keydigs){
          digers.push(new Diger(keydigs[keydig], null, derivationCodes.oneCharCode.Blake3_256, blakeInstance))
        }
        for(let diger in digers){
          digs.push(digers[diger].qb64());
        }
 
        let digArray = ['EmB26yMzroICh-opKNdkYyP000kwevU18WQI95JaJDjY',
        'EO4CXp8gs0yJg1fFhJLs5hH6neqJwhFEY7vrJEdPe87I',
        'ELWWZEyBpjrfM1UU0n31KIyIXllrCoLEOI5UHD9x7WxI']
 
        assert.deepStrictEqual(digs ,digArray )
          let kints = []
        for(let diger in digers){ let i =    bignum.fromBuffer(digers[diger].raw())
        //parseInt(qb2); // int.from_bytes(qb2, 'big')
        console.log("qb2 Value of i = ",i.toString())
        kints.push(BigInt(i.toString()))
        }
        
        let sint =  bignum.fromBuffer(sithdiger.raw())
        sint = BigInt(sint.toString())
        console.log("Value of sint ",sint, (sint.toString()).length)
        for(let kint in kints){sint ^= kints[kint]}
        

        // const buf = Buffer.allocUnsafe(rawSize(derivationCodes.oneCharCode.Blake3_256)); 
        // let  raw =  buf.writeBigInt64BE(sint);
        // console.log("Raw length is = ",raw.length)
      
      let  raw = bignum(sint).toBuffer({
        endian : 'big',
        size : rawSize(derivationCodes.oneCharCode.Blake3_256), // number of bytes in each word
    })
    console.log("Value of Raw and string are : ",raw , '\n',raw.toString(), '\n\n',raw.length)
      // sint.to_bytes( Matter._rawSize(MtrDex.Blake3_256), 'big')
      let rawBuf = Buffer.from('\x0f\xc6/\x0e\xb5\xef\x1a\xe6\x88U\x9e\xbd^\xc0U\x03\x96\r\xda\x93S}\x03\x85\xc2\x07\xa5\xa1Q\xdeX\xab','binary')
     // assert.deepStrictEqual(raw.toString(), rawBuf.toString())
     //   # assert raw == (b'\x0f\xc6/\x0e\xb5\xef\x1a\xe6\x88U\x9e\xbd^\xc0U\x03\x96\r\xda\x93S}\x03\x85\xc2\x07\xa5\xa1Q\xdeX\xab')
 
    
      const kwa = [raw, derivationCodes.oneCharCode.Blake3_256]
     let nexter = new Nexter(null,null,null,null,null, derivationCodes.oneCharCode.Blake3_256,blakeInstance,  ...kwa)      //# defaults provide Blake3_256 digest
    //  assert.deepStrictEqual(nexter.code() ,derivationCodes.oneCharCode.Blake3_256)
    //  assert.deepStrictEqual(nexter.qb64() , 'EtsmHGR3Myic0ywou6ygNXJmxX9LNqcxY8F2XnKpJkPU')
    //   assert.deepStrictEqual((nexter.raw()).length, rawSize(nexter.code()))
    //   assert.deepStrictEqual(nexter.verify(raw),true)

 
 
       nexter = new Nexter(null, null, digs)       // # compute sith from digs using default sith
      assert.deepStrictEqual(nexter.code() ,derivationCodes.oneCharCode.Blake3_256)
      assert.deepStrictEqual((nexter.raw()).length, rawSize(nexter.code()))
      assert.deepStrictEqual(nexter.verify(null, null, null ,digs),true)
      assert.deepStrictEqual(nexter.verify(raw),true)
 
 
 
  // const keys = [verfer.qb64()];

  // let ser = encodeURIComponent(sith + verfer.qb64());
  // //  // (sith + verfer.qb64()).toString('utf-8')
  // // console.log("ser =", ser);
  // let nexter = new Nexter(ser); // # defaults provide Blake3_256 digester
  // assert.deepStrictEqual(nexter.code(), derivationCodes.oneCharCode.Blake3_256);
  // assert.deepStrictEqual(
  //   nexter.qb64(),
  //   'EEV6odWqE1wICGXtkKpOjDxPOWSrF4UAENqYT06C0ECU',
  // );
  // assert.deepStrictEqual(nexter.sith(), null);
  // assert.deepStrictEqual(nexter.keys(), null);
  // assert.deepStrictEqual(
  //   nexter.raw().length,
  //   derivationCodes.CryOneRawSizes[nexter.code()],
  // );
  // assert.deepStrictEqual(nexter.verify(ser), false);
  // assert.deepStrictEqual(
  //   nexter.verify(ser + Buffer.from("ABCDEF", "binary")),
  //   false
  // );

  // nexter = new Nexter(null, sith, keys); // # defaults provide Blake3_256 digester
  // assert.deepStrictEqual(nexter.code(), derivationCodes.oneCharCode.Blake3_256);
  // assert.deepStrictEqual(
  //   nexter.raw().length,
  //   derivationCodes.CryOneRawSizes[nexter.code()],
  // );
  // assert.deepStrictEqual(nexter.sith(), sith);
  // assert.deepStrictEqual(nexter.keys(), keys);

  // let derivedResponse = nexter.derive(sith, keys);
  // console.log('derivedResponse ----------->', derivedResponse);
  // assert.deepStrictEqual(encodeURIComponent(derivedResponse[0].toString()), ser);
  // assert.deepStrictEqual(derivedResponse[1].toString(), sith);
  // assert.deepStrictEqual(derivedResponse[2], keys);

  // assert.deepStrictEqual(nexter.verify(ser), false);
  // assert.deepStrictEqual(
  //   nexter.verify(ser + Buffer.from("ABCDEF", "binary")),
  //   false
  // );
  // // # assert nexter.verify(sith=sith, keys=keys)

  // nexter = new Nexter(null, null, keys); // # compute sith from keys
  // assert.deepStrictEqual(nexter.keys(), keys);
  // assert.deepStrictEqual(nexter.sith(), sith);

  // nexter = new Nexter(null, 1, keys); // # defaults provide Blake3_256 digester
  // assert.deepStrictEqual(nexter.code(), derivationCodes.oneCharCode.Blake3_256);
  // assert.deepStrictEqual(
  //   nexter.raw().length,
  //   derivationCodes.CryOneRawSizes[nexter.code()],
  // );
  // assert.deepStrictEqual(nexter.keys(), keys);
  // assert.deepStrictEqual(nexter.sith(), sith);
  // derivedResponse = nexter.derive(sith, keys);
  // assert.deepStrictEqual(encodeURIComponent(derivedResponse[0].toString()), ser);
  // assert.deepStrictEqual(derivedResponse[1].toString(), sith);
  // assert.deepStrictEqual(derivedResponse[2], keys);

  // assert.deepStrictEqual(nexter.verify(ser), false);
  // assert.deepStrictEqual(
  //   nexter.verify(ser + Buffer.from("ABCDEF", "binary")),
  //   false
  // );

  // const ked = { sith, keys }; // # subsequent event

  // nexter = new Nexter(null, null, null, ked); // # defaults provide Blake3_256 digester
  // assert.deepStrictEqual(nexter.code(), derivationCodes.oneCharCode.Blake3_256);
  // assert.deepStrictEqual(
  //   nexter.raw().length,
  //   derivationCodes.CryOneRawSizes[nexter.code()],
  // );
  // assert.deepStrictEqual(nexter.keys(), keys);
  // assert.deepStrictEqual(nexter.sith(), sith);
  // derivedResponse = nexter.derive(sith, keys);
  // assert.deepStrictEqual(encodeURIComponent(derivedResponse[0].toString()), ser);
  // assert.deepStrictEqual(derivedResponse[1].toString(), sith);
  // assert.deepStrictEqual(derivedResponse[2], keys);
  // assert.deepStrictEqual(nexter.verify(ser), false);
  // assert.deepStrictEqual(
  //   nexter.verify(ser + Buffer.from("ABCDEF", "binary")),
  //   false
  // );
}

/**
 * @description :  Test the support functionality for prefixer subclass of crymat
 */
async function test_prefixer() {
  // raw = null, qb64 = null, qb2 = null, code = codeAndLength.oneCharCode.Ed25519N, index = 0
  await libsodium.ready;
  let preN = 'BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE'
  let pre = 'DrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE'
  let verkey = '\xacr\xda\xc83~\x99r\xaf\xeb`\xc0\x8cR\xd7\xd7\xf69\xc8E\x1e\xd2\xf0=`\xf7\xbf\x8a\x18\x8a`q';
  verkey = Buffer.from(verkey, 'binary');
  let verfer = new Verfer(verkey);
  assert.deepStrictEqual(
    verfer.qb64(),
    'BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE',
  );

  let nxtkey = "\xa6_\x894J\xf25T\xc1\x83#\x06\x98L\xa6\xef\x1a\xb3h\xeaA:x'\xda\x04\x88\xb2\xc4_\xf6\x00";
  nxtkey = Buffer.from(nxtkey, 'binary');
  const nxtfer = new Verfer(
    nxtkey,
    derivationCodes.oneCharCode.Ed25519,
  );
  assert.deepStrictEqual(
    nxtfer.qb64(),
    'Dpl-JNEryNVTBgyMGmEym7xqzaOpBOngn2gSIssRf9gA',
  );

  // test creation given raw and code no derivation

  let prefixer = new Prefixer(verkey);

  // assert.deepStrictEqual(prefixer.code(), derivationCodes.oneCharCode.Ed25519N);
  // assert.deepStrictEqual(
  //   prefixer.raw().length,
  //   derivationCodes.CryOneRawSizes[prefixer.code()],
  // );
  // assert.deepStrictEqual(
  //   prefixer.qb64().length,
  //   derivationCodes.Codes[prefixer.code()].fs,
  // );

  let ked = { k: [prefixer.qb64()], n: '', t: 'icp' };
  // assert.deepEqual(prefixer.verify(ked), true);
  // assert.deepEqual(prefixer.verify(ked,true), false);

  // ked = { k: [prefixer.qb64()], n: 'ABC', t: "icp" };
  // assert.deepEqual(prefixer.verify(ked), false);
  // assert.deepEqual(prefixer.verify(ked,true), false);


  prefixer = new  Prefixer(verkey, derivationCodes.oneCharCode.Ed25519)  //defaults provide Ed25519N prefixer
  // assert.deepStrictEqual(prefixer.code(), derivationCodes.oneCharCode.Ed25519);
  // assert.deepStrictEqual(
  //   prefixer.raw().length,
  //   derivationCodes.CryOneRawSizes[prefixer.code()],
  // );
  // assert.deepStrictEqual(
  //   prefixer.qb64().length,
  //   derivationCodes.Codes[prefixer.code()].fs,
  // );
  // // (raw = null),
  // //   (code = derivationCodes.oneCharCode.Ed25519N),
  // //   (ked = null),
  // //   (seed = null), // secret = null, ...kwa

  ked = { k: [prefixer.qb64()], t: 'icp' };

  // assert.deepEqual(prefixer.verify(ked), true);
  // assert.deepEqual(prefixer.verify(ked,true), false);

  verfer = new Verfer(verkey, derivationCodes.oneCharCode.Ed25519)
  prefixer = new Prefixer(raw=verfer.raw(), derivationCodes.oneCharCode.Ed25519N)
  // assert.deepStrictEqual(prefixer.code(), derivationCodes.oneCharCode.Ed25519N);
  // assert.deepEqual(prefixer.verify(ked), false);
  // assert.deepEqual(prefixer.verify(ked,true), false);


  // # # Test basic derivation from ked
   ked = { k: [verfer.qb64()], t: 'icp', n: '' };
  // dict(k=[verfer.qb64], n="",  t="icp")
  //  prefixer = new Prefixer(null, derivationCodes.oneCharCode.Ed25519, ked)
  //  assert.deepEqual(prefixer.qb64(), verfer.qb64());
  // assert.deepEqual(prefixer.verify(ked), true);
  // assert.deepEqual(prefixer.verify(ked,true), false);




  // verfer = new Verfer(verkey, derivationCodes.oneCharCode.Ed25519N)
  // ked = { k: [verfer.qb64()], t: 'icp', n: '', i: pre };
  // // # ked = dict(k=[verfer.qb64], n="",  t="icp", i=pre)
  // prefixer = new Prefixer(null, derivationCodes.oneCharCode.Ed25519N, ked)    //# verfer code match code but not pre code
  //  assert.deepEqual(prefixer.qb64(), verfer.qb64());
  // assert.deepEqual(prefixer.verify(ked), true);
  // assert.deepEqual(prefixer.verify(ked,true), false);






  // verfer = new Verfer(verkey, derivationCodes.oneCharCode.Ed25519N)
  // ked = { k: [verfer.qb64()], t: 'icp', n: '', i: preN };
  // prefixer = new Prefixer(null, derivationCodes.oneCharCode.Ed25519N, ked)     //# verfer code match code and pre code

  // assert.deepEqual(prefixer.qb64(), verfer.qb64());
  // assert.deepEqual(prefixer.verify(ked), true);
  // assert.deepEqual(prefixer.verify(ked,true), true);



  // verfer = new Verfer(verkey, derivationCodes.oneCharCode.Ed25519N)
  // ked = { k: [verfer.qb64()], t: 'icp', n: '', i: preN };

  // prefixer = new Prefixer(null, derivationCodes.oneCharCode.Ed25519N, ked)         //# verfer code match pre code
  // assert.deepEqual(prefixer.qb64(), verfer.qb64());
  // assert.deepEqual(prefixer.verify(ked), true);
  // assert.deepEqual(prefixer.verify(ked,true), true);
 
 
 
//  # # Test digest derivation from inception ked
    let vs = versify(Versionage, Serials.json, 0)
    let sn = 0
    let ilk = Ilks.icp
    let sith = "1"
    let keys = [new Prefixer(verkey, derivationCodes.oneCharCode.Ed25519).qb64()]
    let nxt = ""
    let toad = 0
    let wits = []
    let cnfg = []

      ked = {
    v: vs.toString(), // version string
    i: "",
    s: sn.toString(16), // # hex string no leading zeros lowercase
    t: ilk,
    kt: sith.toString(16), // # hex string no leading zeros lowercase
    k: keys, // # list of qb64
    n: nxt, // # hash qual Base64
    wt: toad.toString(16), //  # hex string no leading zeros lowercase
    w : wits.toString(16), // # list of qb64 may be empty
    c:cnfg, // # list of config ordered mappings may be empty
  };



  prefixer = new Prefixer(null, derivationCodes.oneCharCode.Blake3_256, ked) 
    // # ked = dict(v=vs,  # version string
    // #            i="",  # qb64 prefix
    // #            s="{:x}".format(sn),  # hex string no leading zeros lowercase
    // #            t=ilk,
    // #            kt=sith, # hex string no leading zeros lowercase
    // #            k=keys,  # list of qb64
    // #            n=nxt,  # hash qual Base64
    // #            wt="{:x}".format(toad),  # hex string no leading zeros lowercase
    // #            w=wits,  # list of qb64 may be empty
    // #            c=cnfg,  # list of config ordered mappings may be empty
    // #            )

    // # prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256)
    // # assert prefixer.qb64 == 'E_P7GKEdbet8OudlQvqILlGn7Fll5q6zfddiSXc-XY5Y'
    // # assert prefixer.verify(ked=ked) == True
    // # assert prefixer.verify(ked=ked, prefixed=True) == False

 
 
  // let ked = {k :[prefixer.qb64()],
  //   n :"", 
  //   t:"icp" }

  //   assert.deepStrictEqual(prefixer.verify(ked) , true)
  // assert prefixer.verify(ked=ked) == True
  // assert prefixer.verify(ked=ked, prefixed=True) == False

  // prefixer = new Prefixer(
  //   verkey,
  //   derivationCodes.oneCharCode.Ed25519,
  //   null,
  //   null,
  //   null,
  // ); // # defaults provide Ed25519N prefixer
  // assert.deepStrictEqual(prefixer.code(), derivationCodes.oneCharCode.Ed25519);
  // assert.deepStrictEqual(
  //   prefixer.raw().length,
  //   derivationCodes.CryOneRawSizes[prefixer.code()],
  // );
  // assert.deepStrictEqual(
  //   prefixer.qb64().length,
  //   derivationCodes.CryOneSizes[prefixer.code()],
  // );

  // ked = { keys: [prefixer.qb64()] };
  // assert.deepStrictEqual(prefixer.verify(ked), true);

  // // raw = null, qb64 = null, qb2 = null, code = codeAndLength.oneCharCode.Ed25519N, index = 0
  // verfer = new Verfer(
  //   verkey,
  //   null,
  //   null,
  //   derivationCodes.oneCharCode.Ed25519,
  //   0,
  // );
  // prefixer = new Prefixer(verfer.raw());
  // assert.deepStrictEqual(prefixer.code(), derivationCodes.oneCharCode.Ed25519N);
  // assert.deepStrictEqual(prefixer.verify(ked), false);

  // //  # # Test basic derivation from ked

  // ked = { keys: [verfer.qb64()], nxt: '' };

  // // raw = null, code = derivation_code.oneCharCode.Ed25519N, ked = null, seed = null, secret = null, ...kwa
  // prefixer = new Prefixer(null, derivationCodes.oneCharCode.Ed25519, ked);
  // assert.deepStrictEqual(prefixer.qb64(), verfer.qb64());
  // assert.deepStrictEqual(prefixer.verify(ked), true);

  // verfer = new Verfer(
  //   verkey,
  //   null,
  //   null,
  //   derivationCodes.oneCharCode.Ed25519N,
  //   0,
  // );
  // ked = { keys: [verfer.qb64()], nxt: '' };
  // prefixer = new Prefixer(null, derivationCodes.oneCharCode.Ed25519N, ked);

  // assert.deepStrictEqual(prefixer.qb64(), verfer.qb64());
  // assert.deepStrictEqual(prefixer.verify(ked), true);

  // // # # Test digest derivation from inception ked
  // ked = { keys: [verfer.qb64()], nxt: 'ABCD' };
  // let vs = versify(Versionage, Serials.json, 0);
  // let sn = 0;
  // let ilk = Ilks.icp;
  // let sith = 1;
  // prefixer = new Crymat(
  //   verkey,
  //   null,
  //   null,
  //   derivationCodes.oneCharCode.Ed25519,
  // );
  // keys = [prefixer.qb64()];
  // let nxt = '';
  // let toad = 0;
  // let wits = [];
  // let cnfg = [];
  // console.log('key is --------->', vs);
  // ked = {
  //   vs: vs.toString(), // version string
  //   pre: '', // # qb64 prefix
  //   sn: sn.toString(16), // # hex string no leading zeros lowercase
  //   ilk,
  //   sith: sith.toString(16), // # hex string no leading zeros lowercase
  //   keys, // # list of qb64
  //   nxt, // # hash qual Base64
  //   toad: toad.toString(16), //  # hex string no leading zeros lowercase
  //   wits, // # list of qb64 may be empty
  //   cnfg, // # list of config ordered mappings may be empty
  // };
  // // util.pad(size.toString(16), VERRAWSIZE);
  // // console.log("key is --------->", keys);
  // let prefixer1 = new Prefixer(
  //   null,
  //   derivationCodes.oneCharCode.Blake3_256,
  //   ked,
  // );

  // assert.deepStrictEqual(
  //   prefixer1.qb64(),
  //   'ErxNJufX5oaagQE3qNtzJSZvLJcmtwRK3zJqTyuQfMmI',
  // );
  // assert.deepStrictEqual(prefixer1.verify(ked, null), true);

  // // # # Test digest derivation from inception ked

  // const nexter = new Nexter(null, 1, [nxtfer.qb64()]);

  // ked = {
  //   vs: vs.toString(), // version string
  //   pre: '', // # qb64 prefix
  //   sn: sn.toString(16), // # hex string no leading zeros lowercase
  //   ilk,
  //   sith: sith.toString(16), // # hex string no leading zeros lowercase
  //   keys, // # list of qb64
  //   nxt, // # hash qual Base64
  //   toad: toad.toString(16), //  # hex string no leading zeros lowercase
  //   wits, // # list of qb64 may be empty
  //   cnfg, // # list of config ordered mappings may be empty
  // };

  // prefixer1 = new Prefixer(
  //   null,
  //   derivationCodes.oneCharCode.Blake3_256,
  //   ked,
  // );
  // assert.deepStrictEqual(
  //   prefixer1.qb64(),
  //   'ErxNJufX5oaagQE3qNtzJSZvLJcmtwRK3zJqTyuQfMmI',
  // );
  // assert.deepStrictEqual(prefixer1.verify(ked, null), true);

  // const perm = [];
  // const seal = {
  //   pre: 'EkbeB57LYWRYNqg4xarckyfd_LsaH0J350WmOdvMwU_Q',
  //   sn: '2',
  //   ilk: Ilks.ixn,
  //   dig: 'E03rxRmMcP2-I2Gd0sUhlYwjk8KEz5gNGxPwPg-sGJds',
  // };

  // ked = {
  //   vs: vs.toString(), // version string
  //   pre: '', // # qb64 prefix
  //   sn: sn.toString(16), // # hex string no leading zeros lowercase
  //   ilk: Ilks.dip,
  //   sith: sith.toString(16), // # hex string no leading zeros lowercase
  //   keys, // # list of qb64
  //   nxt: nexter.qb64(), // # hash qual Base64
  //   toad: toad.toString(16), //  # hex string no leading zeros lowercase
  //   wits, // # list of qb64 may be empty
  //   perm: cnfg,
  //   seal, // # list of config ordered mappings may be empty
  // };

  // prefixer1 = new Prefixer(
  //   null,
  //   derivationCodes.oneCharCode.Blake3_256,
  //   ked,
  // );
  // assert.deepStrictEqual(
  //   prefixer1.qb64(),
  //   'ErxNJufX5oaagQE3qNtzJSZvLJcmtwRK3zJqTyuQfMmI',
  // );
  // assert.deepStrictEqual(prefixer1.verify(ked, null), true);

  // //   // # #  Test signature derivation

  // let seed = libsodium.randombytes_buf(libsodium.crypto_sign_SEEDBYTES);
  // const seed1 = '\xdf\x95\xf9\xbcK@s="\xee\x95w\xbf>F&\xbb\x82\x8f)\x95\xb9\xc0\x1eS\x1b{Lt\xcfH\xa6';
  // seed = Buffer.from(seed1, 'binary');
  // const signer = new Signer(seed, derivationCodes.oneCharCode.Ed25519_Seed, true, libsodium);

  // secret = signer.qb64();
  // assert.deepStrictEqual(
  //   secret,
  //   'A35X5vEtAcz0i7pV3vz5GJruCjymVucAeUxt7THTPSKY',
  // );

  // vs = versify(Versionage, Serials.json, 0);
  // sn = 0;
  // ilk = Ilks.icp;
  // sith = 1;
  // keys = [signer.verfer().qb64()];
  // nxt = '';
  // toad = 0;
  // wits = [];
  // cnfg = [];

  // const nexter1 = new Nexter(null, 1, [nxtfer.qb64()]);
  // const t = keys[0];
  // console.log(
  //   'Keys are ******************************************************',
  //   t.toString(),
  // );
  // ked = {
  //   vs: vs.toString(), // version string
  //   pre: '', // # qb64 prefix
  //   sn: sn.toString(16), // # hex string no leading zeros lowercase
  //   ilk,
  //   sith: sith.toString(16), // # hex string no leading zeros lowercase
  //   keys, // # list of qb64
  //   nxt: nexter1.qb64(), // # hash qual Base64
  //   toad: toad.toString(16), //  # hex string no leading zeros lowercase
  //   wits, // # list of qb64 may be empty
  //   cnfg,
  //   // # list of config ordered mappings may be empty
  // };

  // prefixer1 = new Prefixer(
  //   null,
  //   derivationCodes.twoCharCode.Ed25519,
  //   ked,
  //   seed,
  // );
  // assert.deepStrictEqual(
  //   prefixer1.qb64(),
  //   '0B616nSPoo4ZIO997mZJQTMiys1oBPGWM8skFjqUDIXQVKA3iS1BlUjvctbYFK7p3e__pQ4hMIdgmiwsXUr8JiDg',
  // );
  // assert.deepStrictEqual(prefixer1.verify(ked), true);
  // assert.deepStrictEqual(prefixer1.qb64(), '0B616nSPoo4ZIO997mZJQTMiys1oBPGWM8skFjqUDIXQVKA3iS1BlUjvctbYFK7p3e__pQ4hMIdgmiwsXUr8JiDg');

  // # assert
  // # assert prefixer.verify(ked=ked) == True

  // # prefixer = Prefixer(ked=ked, code=CryTwoDex.Ed25519, secret=secret)
  // # assert prefixer.qb64 == '0B0uVeeaCtXTAj04_27g5pSKjXouQaC1mHcWswzkL7Jk0XC0yTyNnIvhaXnSxGbzY8WaPv63iAfWhJ81MKACRuAQ'
  // # assert prefixer.verify(ked=ked) == True
}

/**
 * @description   Test the support functionality for attached signature cryptographic material
 */
async function test_sigmat() {
  assert.deepStrictEqual(derivationCodes.SigTwoCodex.Ed25519, 'A'); // # Ed25519 signature.
  assert.deepStrictEqual(derivationCodes.SigTwoCodex.ECDSA_256k1, 'B'); // # ECDSA secp256k1 signature.

  assert.deepStrictEqual(
    derivationCodes.SigTwoSizes[derivationCodes.SigTwoCodex.Ed25519],
    88,
  );
  assert.deepStrictEqual(
    derivationCodes.SigTwoSizes[derivationCodes.SigTwoCodex.ECDSA_256k1],
    88,
  );

  let cs = stringToBnary.intToB64(0);
  console.log('------------------->', cs);
  assert.deepStrictEqual(cs, 'A');
  let i = stringToBnary.b64ToInt('A');
  assert.deepStrictEqual(i, 0);

  cs = stringToBnary.intToB64(27);
  assert.deepStrictEqual(cs, 'b');
  i = stringToBnary.b64ToInt(cs);
  assert.deepStrictEqual(i, 27);

  cs = stringToBnary.intToB64(27, (l = 2));
  assert.deepStrictEqual(cs, 'Ab');
  i = stringToBnary.b64ToInt(cs);
  assert.deepStrictEqual(i, 27);

  cs = stringToBnary.intToB64(80);
  assert.deepStrictEqual(cs, 'BQ');
  i = stringToBnary.b64ToInt(cs);
  assert.deepStrictEqual(i, 80);

  cs = stringToBnary.intToB64(4095);
  assert.deepStrictEqual(cs, '__');
  i = stringToBnary.b64ToInt(cs);
  assert.deepStrictEqual(i, 4095);

  cs = stringToBnary.intToB64(4096);
  assert.deepStrictEqual(cs, 'BAA');
  i = stringToBnary.b64ToInt(cs);
  assert.deepStrictEqual(i, 4096);

  cs = stringToBnary.intToB64(6011);
  assert.deepStrictEqual(cs, 'Bd7');
  i = stringToBnary.b64ToInt(cs);
  assert.deepStrictEqual(i, 6011);

  // # Test attached signature code (empty raw)
  let qsc = derivationCodes.SigCntCodex.Base64 + stringToBnary.intToB64(0, 2);
  console.log('qsc---------------->', qsc);
  assert.deepStrictEqual(qsc, '-AAA');
  let sigmat = new SigMat(
    Buffer.from('', 'binary'),
    null,
    null,
    derivationCodes.SigCntCodex.Base64,
    0,
  );
  assert.deepStrictEqual(sigmat.raw(), Buffer.from('', 'binary'));
  assert.deepStrictEqual(sigmat.code(), derivationCodes.SigCntCodex.Base64);
  assert.deepStrictEqual(sigmat.index(), 0);
  assert.deepStrictEqual(sigmat.qb64(), qsc);

  // ------------ NEED to test this again ------------------
  console.log('value ooooooooooooooooooooooo', sigmat.qb2());
  console.log(
    'value ======================',
    Buffer.from('\xf8\x00\x00', 'binary').toString(),
  );
  Base64.decode(sigmat.qb2()).toString('utf-8');
  assert.deepStrictEqual(
    sigmat.qb2(),
    Buffer.from('\xf8\x00\x00', 'binary').toString(),
  );

  sigmat = new SigMat(
    null,
    qsc,
    null,
    derivationCodes.SigTwoCodex.Ed25519,
    0,
  );
  assert.deepStrictEqual(sigmat.raw(), Buffer.from('', 'binary'));
  assert.deepStrictEqual(sigmat.code(), derivationCodes.SigCntCodex.Base64);
  assert.deepStrictEqual(sigmat.index(), 0);
  assert.deepStrictEqual(sigmat.qb64(), qsc);
  assert.deepStrictEqual(
    sigmat.qb2(),
    Buffer.from('\xf8\x00\x00', 'binary').toString(),
  );

  const idx = 5;
  qsc = derivationCodes.SigCntCodex.Base64 + stringToBnary.intToB64(idx, 2);
  assert.deepStrictEqual(qsc, '-AAF');
  sigmat = new SigMat(
    Buffer.from('', 'binary'),
    null,
    null,
    derivationCodes.SigCntCodex.Base64,
    idx,
  );
  assert.deepStrictEqual(sigmat.raw(), Buffer.from('', 'binary'));
  assert.deepStrictEqual(sigmat.code(), derivationCodes.SigCntCodex.Base64);
  assert.deepStrictEqual(sigmat.index(), 5);
  assert.deepStrictEqual(sigmat.qb64(), qsc);
  assert.deepStrictEqual(
    sigmat.qb2(),
    Buffer.from('\xf8\x00\x05', 'binary').toString(),
  );

  // =================== Signature testing ====================

  let sig = "\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp\x0e'm\x8f@\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)\xde\xca"
    + '\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t';

  sig = Buffer.from(sig, 'binary');
  assert.equal(sig.length, 64);
  const sig64 = Base64.encode(sig);

  console.log('base 64 is ----->', decodeURIComponent(Base64.encode(sig)));
  // assert.deepStrictEqual(sig64, 'mdI8OSQkMJ9r+xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K/H9+1298F4Id1DxvIoEmCQ==')

  let qsig64 = 'AAmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ';
  const encoded_data = Base64.decode(encodeURIComponent(qsig64));
  console.log('encoded_data =======================>', encoded_data.length);
  assert.equal(qsig64.length, 88);
  const qsig64b = Base64.encode(qsig64);
  let qbin = Base64.decode(Buffer.from(qsig64b, 'binary'));
  //  console.log("qbin ------------------------>",qbin.length)
  assert.equal(qbin.length, 66);
  console.log('qbin --------------_>', qbin);

  qbin = '\x00\t\x9d#\xc3\x92BC\t\xf6\xbf\xb1\x8a\x08\xc4\x07!#"\xe6\xbb,q\xf7\x00\xe2v\xd8\xf4\n\xaaX\xcc\x86\xe8\\\x82\x1fg\x19\x17\n\x9e\xcc\xf9*\xf2\x9d\xec\xaf\xc7\xf7\xedv\xf7\xc1x!\xddC\xc6\xf2(\x12`\x90';

  qbin = Buffer.from(qbin, 'binary');

  sigmat = new SigMat(sig);

  assert.deepStrictEqual(sigmat.raw(), sig);
  assert.deepStrictEqual(sigmat.code(), derivationCodes.SigTwoCodex.Ed25519);
  assert.deepStrictEqual(sigmat.index(), 0);
  assert.deepStrictEqual(sigmat.qb64(), qsig64);
  assert.deepStrictEqual(sigmat.qb2(), qbin.toString());

  sigmat = new SigMat(
    null,
    qsig64,
    null,
    derivationCodes.SigTwoCodex.Ed25519,
    0,
  );
  assert.deepStrictEqual(sigmat.raw(), sig);
  assert.deepStrictEqual(sigmat.code(), derivationCodes.SigTwoCodex.Ed25519);
  assert.deepStrictEqual(sigmat.index(), 0);

  // # # test wrong size of qb64s
  const longqsig64 = `${qsig64}ABCD`;

  const oksigmat = new SigMat(null, longqsig64, null);
  console.log('latest length of qsig64 is ----------->', oksigmat.qb64());
  assert.deepStrictEqual(
    oksigmat.qb64().length,
    derivationCodes.SigSizes[oksigmat.code()],
  );

  // # test auto convert bytes to str

  sigmat = new SigMat(null, encodeURIComponent(qsig64), null);

  assert.deepStrictEqual(sigmat.raw(), sig);
  assert.deepStrictEqual(sigmat.code(), derivationCodes.SigTwoCodex.Ed25519);
  assert.deepStrictEqual(sigmat.index(), 0);
  assert.deepStrictEqual(sigmat.qb64(), qsig64);
  assert.deepStrictEqual(sigmat.qb64(), encodeURIComponent(qsig64));

  sigmat = new SigMat(null, null, qbin);

  assert.deepStrictEqual(sigmat.raw(), sig);
  assert.deepStrictEqual(sigmat.code(), derivationCodes.SigTwoCodex.Ed25519);
  assert.deepStrictEqual(sigmat.index(), 0);

  sigmat = new SigMat(
    sig,
    null,
    null,
    derivationCodes.SigTwoCodex.Ed25519,
    5,
  );
  assert.deepStrictEqual(sigmat.raw(), sig);
  assert.deepStrictEqual(sigmat.code(), derivationCodes.SigTwoCodex.Ed25519);
  assert.deepStrictEqual(sigmat.index(), 5);

  // AFmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ
  // AFmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEm

  qsig64 = 'AFmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ';
  //  assert.deepStrictEqual(sigmat.qb64(), qsig64)

  qbin = '\x00Y\x9d#\xc3\x92BC\t\xf6\xbf\xb1\x8a\x08\xc4\x07!#"\xe6\xbb,q\xf7\x00\xe2v\xd8\xf4\n\xaaX\xcc\x86\xe8\\\x82\x1fg\x19\x17\n\x9e\xcc\xf9*\xf2\x9d\xec\xaf\xc7\xf7\xedv\xf7\xc1x!\xddC\xc6\xf2(\x12`\x90';
  // #         b'\x00\xe2v\xd8\xf4\n\xaaX\xcc\x86\xe8\\\x82\x1fg\x19\x17\n\x9e\xcc'
  // #         b'\xf9*\xf2\x9d\xec\xaf\xc7\xf7\xedv\xf7\xc1x!\xddC\xc6\xf2(\x12`\x90')
  qbin = Buffer.from(qbin, 'binary');
  // assert.deepStrictEqual(sigmat.qb2(), qbin.toString())

  sigmat = new SigMat(null, qsig64, null);
  assert.deepStrictEqual(sigmat.raw(), sig);
  assert.deepStrictEqual(sigmat.code(), derivationCodes.SigTwoCodex.Ed25519);
  assert.deepStrictEqual(sigmat.index(), 5);

  sigmat = new SigMat(null, null, qbin);
  assert.deepStrictEqual(sigmat.raw(), sig);
  assert.deepStrictEqual(sigmat.code(), derivationCodes.SigTwoCodex.Ed25519);
  assert.deepStrictEqual(sigmat.index(), 5);
}

/**
 * @description Test the support functionality for verifier subclass of crymat
 */
async function test_verfer() {
  await libsodium.ready;
  let seed = libsodium.randombytes_buf(libsodium.crypto_sign_SEEDBYTES);
  const keypair = libsodium.crypto_sign_seed_keypair(seed);
  // console.log("verkey, sigkey",keypair.privateKey, keypair.publicKey)
  let verkey = keypair.publicKey;
  let sigkey = keypair.privateKey;
  verkey = String.fromCharCode.apply(null, verkey);
  console.log("Value of Verkey =",verkey)
  verkey = Buffer.from(verkey, 'binary');
  console.log('verkey-------------->', verkey);
  const verfer = new Verfer(
    Buffer.from(verkey, 'binary'),
    derivationCodes.oneCharCode.Ed25519N,
  );
  assert.deepStrictEqual(verfer.raw(), verkey);
  assert.deepStrictEqual(verfer.code(), derivationCodes.oneCharCode.Ed25519N);

  // const encoder = new util.TextEncoder('utf-8');
  // abcdefghijklmnopqrstuvwxyz0123456789
  const ser = Buffer.from('abcdefghijklmnopqrstuvwxyz0123456789', 'binary');
  seed = Buffer.from(seed, 'binary');
  sigkey = Buffer.from(sigkey, 'binary');
  let sig =  libsodium.crypto_sign_detached(
    ser, Buffer.concat([seed,verkey])
   // seed + sigkey
  ); //# sigkey = seed + verkey

  result = verfer.verify(sig, ser);
  assert.deepStrictEqual(result, true);
}

/**
 * @description  Test the support functionality for Serder key event serialization deserialization
 */
async function test_serder() {
  const e1 = {
    vs: versify(null, Serials.json, 0),
    pre: 'ABCDEFG',
    sn: '0001',
    ilk: 'rot',
  };
  console.log('e1 is --------------------->', e1);
  const Version = Versionage;

  const serder = new Serder(null, e1);
  serder.set_kind();

  serder.set_raw(Buffer.from(JSON.stringify(e1), 'binary'));

  assert.deepStrictEqual(serder.getKed, e1);
  assert.deepStrictEqual(serder.getKind, Serials.json);
  assert.deepStrictEqual(serder.version(), Version);

  assert.deepStrictEqual(
    serder.dig(),
    'EaDVEkrFdx8W0ZZAsfwf9mjxhgBt6PvfCmFPdr7RIcfY',
  );
  assert.deepStrictEqual(
    serder.digb(),
    Buffer.from('EaDVEkrFdx8W0ZZAsfwf9mjxhgBt6PvfCmFPdr7RIcfY', 'binary'),
  );
  assert.deepStrictEqual(serder.size(), 66);
  assert.deepStrictEqual(
    serder.raw(),
    Buffer.from(
      '{"vs":"KERI10JSON000042_","pre":"ABCDEFG","sn":"0001","ilk":"rot"}',
      'binary',
    ),
  );

  // ------------------------- SERDER VERFER IS PENDING -----------------------
  assert.deepStrictEqual(serder.verfers(), []);

  const e1s = Buffer.from(JSON.stringify(e1), 'binary');
  console.log('Els length is ------>', e1s.length);
  let vs = versify(null, Serials.json, e1s.length);
  assert.equal(vs, 'KERI10JSON000042_');

  // // let   [kind1, vers1, size1] = serder._sniff(e1s.slice(0,VERFULLSIZE))
  // //  console.log("e1s[:MINSNIFFSIZE] =========================>",e1s.slice(0,VERFULLSIZE))
  // let [kind1, vers1, size1] = serder._sniff(e1s.slice(0,MINSNIFFSIZE ))
  // // assert.deepStrictEqual(kind1,Serials.json)
  // // assert.deepStrictEqual(size1,66)

  const [kind1, vers1, size1] = serder.sniff(e1s);
  // assert.deepStrictEqual(kind1,Serials.json)
  //  assert.deepStrictEqual(size1,66)
  const e1ss = e1s + Buffer.from('extra attached at the end.', 'binary');
  const [ked1, knd1, vrs1, siz1] = serder.inhale(e1ss);
  assert.deepStrictEqual(ked1, e1);
  assert.deepStrictEqual(knd1, kind1);
  assert.deepStrictEqual(vrs1, vers1);
  assert.deepStrictEqual(siz1, size1);

  const [raw1, knd2, ked2, ver1] = serder.exhale(e1);
  assert.deepStrictEqual(Buffer.from(raw1, 'binary'), e1s);
  assert.deepStrictEqual(knd2, kind1);
  assert.deepStrictEqual(ked2, e1);
  assert.deepStrictEqual(vrs1, vers1);

  const e2 = {
    vs: versify(null, Serials.json, 0),
    pre: 'ABCDEFG',
    sn: '0001',
    ilk: 'rot',
  };
  e2.vs = versify(null, Serials.mgpk, 0);
  console.log('==========================>', e2.vs);
  const e2s = encode(e2);
  const e2s1 = e2s;
  const msgBuffer = Buffer.from(
    '\x84\xa2vs\xb1KERI10MGPK000000_\xa3pre\xa7ABCDEFG\xa2sn\xa40001\xa3ilk\xa3rot',
    'binary',
  );
  assert.deepStrictEqual(e2s, msgBuffer);

  vs = versify(null, Serials.mgpk, e2s.length); // # use real length
  assert.deepStrictEqual(vs, 'KERI10MGPK000032_');
  e2s1.vs = versify(null, Serials.mgpk, e2s.length);
  assert.deepStrictEqual(e2s1, e2s);
  // console.log("e2s ==========+>",decode(e2s))
  // console.log("e2 ==========+>",encode(e2))
  // console.log("if true or false ",(e2s == encode(e2)))
  assert.deepStrictEqual(decode(e2s), e2);

  const e3 = {
    vs: versify(null, Serials.json, 0),
    pre: 'ABCDEFG',
    sn: '0001',
    ilk: 'rot',
  };
  e3.vs = versify(null, Serials.cbor, 0);
  let e3s = cbor.encode(e3);
  assert.deepEqual(
    e3s,
    Buffer.from(
      '\xa4bvsqKERI10CBOR000000_cpregABCDEFGbsnd0001cilkcrot',
      'binary',
    ),
  );
  vs = versify(null, Serials.cbor, e3s.length); // # use real length
  assert.equal(vs, 'KERI10CBOR000032_');
  e3.vs = vs; // # has real length

  const e5 = {
    vs: versify(null, Serials.cbor, 0),
    pre: 'ABCDEFG',
    sn: '0001',
    ilk: 'rot',
  };
  e3s = cbor.encode(e3);
  console.log('e3s =============>', cbor.decode(e3s));
  const [kind3, vers3, size3] = serder.sniff(e3s.slice(0, MINSNIFFSIZE));
  assert.deepStrictEqual(kind3, Serials.cbor);
  assert.equal(size3, 50);

  const [kind3a, vers3a, size3a] = serder.sniff(e3s);
  assert.deepStrictEqual(kind3a, Serials.cbor);
  assert.deepStrictEqual(size3a, 50);
  // let e3ss = cbor.encode(e3) +
  const encodedText = cbor.encode('extra attached at the end.');
  const encodedE3 = cbor.encode(e3);
  const e3ss = Buffer.concat([encodedE3, encodedText]);
  console.log('DECODING CBROR', e3ss);

  const [ked3b, knd3b, vrs3b, siz3b] = serder.inhale(e3ss);

  // --------------------- This case is getting failed ---------------------
  assert.deepStrictEqual(ked3b[0], e3);
  // ----------------------------
  assert.deepStrictEqual(knd3b, kind3);
  assert.deepStrictEqual(vrs3b, vers3);
  assert.deepStrictEqual(siz3b, size3);

  // # with pytest.raises(ShortageError):  # test too short
  // #     ked3, knd3, vrs3, siz3 = serder._inhale(e3ss[:size3-1])
  console.log('e3 is- --------->', e5);
  // let [raw3c, knd3c, ked3c, ver3c] = serder.exhale(e5);
  // assert.deepStrictEqual(raw3c, e3s);
  // assert.deepStrictEqual(knd3c, kind3);
  // assert.deepStrictEqual(ked3c, e3);
  // assert.deepStrictEqual(vrs3b, vers3a);

  // console.log(
  //   "versify(null,Serials.json,0) =================>",
  //   versify(null, Serials.json, 0)
  // );
  // let e7 = {
  //   vs: versify(null, Serials.json, e1s.length),
  //   pre: "ABCDEFG",
  //   sn: "0001",
  //   ilk: "rot",
  // };
  // let t =
  //   Buffer.from(JSON.stringify(e7), "binary") +
  //   Buffer.from("extra attached at the end.", "binary");
  // console.log("vaue of t is --->", t);
  // let evt1 = new Serder(t);
  // evt1.set_raw(t);
  // console.log("e3ss =============>", t);
  // assert.deepStrictEqual(evt1.kind(), kind1);
  // assert.deepStrictEqual(evt1.raw(), e1s);
  // assert.deepStrictEqual(evt1.ked(), ked1);
  // assert.deepStrictEqual(evt1.size(), size1);
  // assert.deepStrictEqual(evt1.raw().toString(), t.slice(0, size1));
  // assert.deepStrictEqual(evt1.version(), vers1);

  // # # test digest properties .diger and .dig
  // # assert evt1.diger.qb64 == evt1.dig
  // # assert evt1.diger.code == CryOneDex.Blake3_256
  // # assert len(evt1.diger.raw) == 32
  // # assert len(evt1.dig) == 44
  // # assert len(evt1.dig) == CryOneSizes[CryOneDex.Blake3_256]
  // # assert evt1.dig == 'EaDVEkrFdx8W0ZZAsfwf9mjxhgBt6PvfCmFPdr7RIcfY'
  // # assert evt1.diger.verify(evt1.raw)

  // console.log(
  //   "versify(null,Serials.json,0) =================>",
  //   versify(null, Serials.json, 0)
  // );
  //  e7 = {
  //   vs: versify(null, Serials.json, e1s.length),
  //   pre: "ABCDEFG",
  //   sn: "0001",
  //   ilk: "rot",
  // };
  //  t =
  //   Buffer.from(JSON.stringify(e7), "binary") +
  //   Buffer.from("extra attached at the end.", "binary");
  // console.log("vaue of t is --->", t);
  //  evt1 = new Serder(null, ked1);
  // evt1.set_raw(t);
  // assert.deepStrictEqual(evt1.kind(), kind1);
  // assert.deepStrictEqual(evt1.raw(), e1s);
  // assert.deepStrictEqual(evt1.ked(), ked1);
  // assert.deepStrictEqual(evt1.size(), size1);
  // assert.deepStrictEqual(evt1.raw().toString(), t.slice(0, size1));
  // assert.deepStrictEqual(evt1.version(), vers1);

  // let evt2 = new  Serder(e2ss)
  // # assert evt2.kind == kind2
  // # assert evt2.raw == e2s
  // # assert evt2.ked == ked2
  // # assert evt2.version == vers2

  // # evt2 = Serder(ked=ked2)
  // # assert evt2.kind == kind2
  // # assert evt2.raw == e2s
  // # assert evt2.ked == ked2
  // # assert evt2.size == size2
  // # assert evt2.raw == e2ss[:size2]
  // # assert evt2.version == vers2

  // # evt3 = Serder(raw=e3ss)
  // # assert evt3.kind == kind3
  // # assert evt3.raw == e3s
  // # assert evt3.ked == ked3
  // # assert evt3.version == vers3

  // # evt3 = Serder(ked=ked3)
  // # assert evt3.kind == kind3
  // # assert evt3.raw == e3s
  // # assert evt3.ked == ked3
  // # assert evt3.size == size3
  // # assert evt3.raw == e3ss[:size3]
  // # assert evt3.version == vers3

  // # #  round trip
  // # evt2 = Serder(ked=evt1.ked)
  // # assert evt2.kind == evt1.kind
  // # assert evt2.raw == evt1.raw
  // # assert evt2.ked == evt1.ked
  // # assert evt2.size == evt1.size
  // # assert evt2.version == vers2

  // # # Test change in kind by Serder
  // # evt1 = Serder(ked=ked1, kind=Serials.mgpk)  # ked is json but kind mgpk
  // # assert evt1.kind == kind2
  // # assert evt1.raw == e2s
  // # assert evt1.ked == ked2
  // # assert evt1.size == size2
  // # assert evt1.raw == e2ss[:size2]
  // # assert evt1.version == vers1

  // # #  round trip
  // # evt2 = Serder(raw=evt1.raw)
  // # assert evt2.kind == evt1.kind
  // # assert evt2.raw == evt1.raw
  // # assert evt2.ked == evt1.ked
  // # assert evt2.size == evt1.size
  // # assert evt2.version == vers2

  // # evt1 = Serder(ked=ked1, kind=Serials.cbor)  # ked is json but kind mgpk
  // # assert evt1.kind == kind3
  // # assert evt1.raw == e3s
  // # assert evt1.ked == ked3
  // # assert evt1.size == size3
  // # assert evt1.raw == e3ss[:size3]
  // # assert evt1.version == vers1

  // # #  round trip
  // # evt2 = Serder(raw=evt1.raw)
  // # assert evt2.kind == evt1.kind
  // # assert evt2.raw == evt1.raw
  // # assert evt2.ked == evt1.ked
  // # assert evt2.size == evt1.size
  // # assert evt2.version == vers2

  // # # use kind setter property
  // # assert evt2.kind == Serials.cbor
  // # evt2.kind = Serials.json
  // # assert evt2.kind == Serials.json
  // # knd, version, size = Deversify(evt2.ked['vs'])
  // # assert knd == Serials.json
  // """Done Test """
}

async function test_sigver() {
  await libsodium.ready;
  const qsig64 = '0BmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ';

  let sigver = new Sigver(
    null,
    derivationCodes.twoCharCode.Ed25519,
    null,
    0,
    qsig64,
  );
  console.log('sigver.verfer() ========================>', sigver.verfer());
  const set_verfer = sigver.verfer();
  sigver.setVerfer(set_verfer);
  assert.deepStrictEqual(sigver.code(), derivationCodes.twoCharCode.Ed25519);
  assert.deepStrictEqual(sigver.qb64(), qsig64);
  assert.deepStrictEqual(sigver.verfer(), null);

  const keypair = libsodium.crypto_sign_keypair();
  const verkey = Buffer.from(keypair.publicKey, 'binary');
  const sigkey = Buffer.from(keypair.privateKey, 'binary');
  const verfer = new Verfer(
    verkey,
    null,
    null,
    derivationCodes.oneCharCode.Ed25519N,
    0,
  );

  sigver.setVerfer(verfer);
  assert.deepStrictEqual(sigver.verfer(), verfer);

  sigver = new Sigver(
    null,
    derivationCodes.twoCharCode.Ed25519,
    verfer,
    0,
    qsig64,
  );
  assert.deepStrictEqual(sigver.verfer(), verfer);
}

async function test_signer() {
  await libsodium.ready;
  const signer = new Signer(
    null,
    derivationCodes.oneCharCode.Ed25519_Seed,
    true,
    null,
    null,
  ); // # defaults provide Ed25519 signer Ed25519 verfer
  assert.deepStrictEqual(
    signer.code(),
    derivationCodes.oneCharCode.Ed25519_Seed,
  );
  assert.deepStrictEqual(
    signer.raw().length,
    derivationCodes.CryOneRawSizes[signer.code()],
  );
  assert.deepStrictEqual(
    signer.verfer().code(),
    derivationCodes.oneCharCode.Ed25519,
  );
  assert.deepStrictEqual(
    signer.verfer().raw().length,
    derivationCodes.CryOneRawSizes[[signer.verfer().code()]],
  );

  // # create something to sign and verify

  const ser = Buffer.from('abcdefghijklmnopqrstuvwxyz0123456789', 'binary');
  const mattr =  signer.sign(ser);
    console.log("Value of mattr" ,mattr)
  assert.deepStrictEqual(mattr.code(), derivationCodes.twoCharCode.Ed25519_SIG);
  assert.deepStrictEqual(
    mattr.raw().length,
    derivationCodes.cryAllRawSizes[mattr.code()],
  );
  const _ver3 = signer.verfer();

  const result = _ver3.verify(mattr.raw(), ser);
  assert.deepStrictEqual(result, true);
}

async function test_matter() {
  assert.deepStrictEqual(derivationCodes.Codes.A.hs, 1);
  assert.deepStrictEqual(derivationCodes.Codes.A.ss, 0);
  assert.deepStrictEqual(derivationCodes.Codes.A.fs, 44);

  let verkey = 'iN\x89Gi\xe6\xc3&~\x8bG|%\x90(L\xd6G\xddB\xef`\x07\xd2T\xfc\xe1\xcd.\x9b\xe4#';
 verkey = Buffer.from(verkey, 'binary');
// verkey = Base64.encode(verkey);
// verkey = Buffer.from(verkey, 'binary');
  let prefix = 'BaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM';
  let prefixb = Buffer.from(prefix, 'binary');
  let prebin = '\x05\xa5:%\x1d\xa7\x9b\x0c\x99\xfa-\x1d\xf0\x96@\xa13Y\x1fu\x0b\xbd\x80\x1fIS\xf3\x874\xbao\x90\x8c';
  // console.log('Base64 of verkey = ', Base64.encode(verkey));
  prebin = Buffer.from(prebin,'binary')
  console.log("Valur of prebin is = ",(Buffer.from(prebin,'binary')).length)
  // let matter = new Matter(verkey);
  // console.log("value of Prebin is = ",prebin.toString())
  // assert.deepStrictEqual(matter.raw(), verkey);
  // assert.deepStrictEqual(matter.code(), derivationCodes.allCharcodes.Ed25519N);
  // assert.deepStrictEqual(matter.qb64(), prefix);
  // console.log("Buffer.from(prebin,'binary') ===============>",Base64.encode(matter.qb2()))
  // console.log("value of Prebin is = ",Base64.encode(Buffer.from(prebin, 'binary')))
  // assert.deepStrictEqual(matter.qb2(), Buffer.from(prebin,'binary'));    
  // assert.deepStrictEqual(matter.transferable(), false);
  // assert.deepStrictEqual(matter.digestive(), false);
  // assert.deepStrictEqual(matter.qb64() , Base64.encode(matter.qb2()))      
  // assert.deepStrictEqual(matter.qb2() , Base64.decode(matter.qb64()))    
  // console.log("Length of Raw = ",(matter.raw()).length)
  // matter.exfil(prefixb);
  // assert.deepStrictEqual(matter.raw(), verkey);
  // assert.deepStrictEqual(matter.code(), derivationCodes.allCharcodes.Ed25519N);

  // matter = new Matter(null, null, prefixb);
  // // assert.deepStrictEqual(matter.raw(), verkey);
  // assert.deepStrictEqual(matter.code(), derivationCodes.allCharcodes.Ed25519N);

  // matter = new Matter(null, null, null, prefix);
  // assert.deepStrictEqual(matter.raw(), verkey);
  // assert.deepStrictEqual(matter.code(), derivationCodes.allCharcodes.Ed25519N);

  // matter = new Matter(null, null, null, prefixb);
  // assert.deepStrictEqual(matter.raw(), verkey);
  // assert.deepStrictEqual(matter.code(), derivationCodes.allCharcodes.Ed25519N);


  // // # # test truncates extra bytes from qb64 parameter
  // var longprefix = prefix + "ABCD"  // # extra bytes in size
  //  matter = new Matter(null,derivationCodes.allCharcodes.Ed25519N,null,longprefix)
  //  assert.deepStrictEqual((matter.qb64()).length,derivationCodes.Codes[matter.code()].fs )
 
  // # # test raises ShortageError if not enough bytes in qb64 parameter
  // # shortprefix = prefix[:-4]  # too few bytes in  size
  // # with pytest.raises(ShortageError):
  // #     matter = Matter(qb64=shortprefix)

  //  matter =  new Matter(null,derivationCodes.allCharcodes.Ed25519N,null,null,prebin)
    // console.log("Value of byte = ",`\x04`)
    // console.log("Value of Buffer byte = ",Buffer.from(`\x04`, 'binary'))
    // let c = Buffer.from(`\x04`, 'binary')
    // console.log("Value of C = ",c.toString())
  //  assert.deepStrictEqual(matter.code() , derivationCodes.allCharcodes.Ed25519N)
  //  assert.deepStrictEqual(matter.raw(), verkey)


  // # # test truncates extra bytes from qb2 parameter
  
  let extraChars = Buffer.concat([Buffer.from((1).toString(),'binary'),Buffer.from((2).toString(),'binary'),Buffer.from((3).toString(),'binary'),Buffer.from((4).toString(),'binary'),Buffer.from((5).toString(),'binary')])
  console.log("Length of exttrra char = ",extraChars.length)
  let longprebin = Buffer.concat([prebin,extraChars]) 
  console.log("Length of longprebin = ",longprebin.length)
  //bytearray([1, 2, 3, 4, 5])    //# extra bytes in size
   matter = new Matter(null,derivationCodes.allCharcodes.Ed25519N,null,null,longprebin)
   assert.deepStrictEqual((matter.qb64()).length , derivationCodes.Codes[matter.code()].fs)

  // # # test raises ShortageError if not enough bytes in qb2 parameter
  // # shortprebin = prebin[:-4]  # too few bytes in  size
  // # with pytest.raises(ShortageError):
  // #     matter = Matter(qb2=shortprebin)

  //  matter = new  Matter(null,derivationCodes.allCharcodes.Ed25519N,null,prefixb)   //# test bytes not str
  //  assert.deepStrictEqual(matter.code(), derivationCodes.allCharcodes.Ed25519N)
  //  assert.deepStrictEqual(matter.raw() , verkey)
  //  assert.deepStrictEqual(matter.qb64() , prefix)
  //  assert.deepStrictEqual(matter.qb64b() , prefixb)

  // # # test truncates extra bytes from raw parameter
  //  extraChars = Buffer.concat([Buffer.from((10).toString(),'binary'),Buffer.from((11).toString(),'binary'),Buffer.from((12).toString(),'binary')])

  // let longverkey = Buffer.concat([verkey,extraChars])     //+ bytes([10, 11, 12])  # extra bytes
  //     matter =  new Matter(longverkey)

  // # # test raises ShortageError if not enough bytes in raw parameter
  // # shortverkey =  verkey[:-3]  # not enough bytes
  // # with pytest.raises(RawMaterialError):
  // #     matter = Matter(raw=shortverkey)

  // # # test prefix on full identifier
  // let full = prefix + ":mystuff/mypath/toresource?query=what#fragment"
  //  matter =  new Matter(null,derivationCodes.allCharcodes.Ed25519N,null,full )
  //     assert.deepStrictEqual(matter.code(), derivationCodes.allCharcodes.Ed25519N)
  //  assert.deepStrictEqual(matter.raw() , verkey)
  //  assert.deepStrictEqual(matter.qb64() , prefix)
  //  assert.deepStrictEqual(matter.qb2() , prebin)
  //  assert.deepStrictEqual(matter.transferable() , false)
  //  assert.deepStrictEqual(matter.digestive() , false)

  // # # test nongreedy prefixb on full identifier


    full = prefix + Buffer.from(":mystuff/mypath/toresource?query=what#fragment", 'binary')
   matter =  new Matter(null,derivationCodes.allCharcodes.Ed25519N,full )
  //     assert.deepStrictEqual(matter.code(), derivationCodes.allCharcodes.Ed25519N)
  //  assert.deepStrictEqual(matter.raw() , verkey)
  //  assert.deepStrictEqual(matter.qb64() , prefix)
  //  assert.deepStrictEqual(matter.qb2() , prebin)
  //  assert.deepStrictEqual(matter.transferable() , false)
  //  assert.deepStrictEqual(matter.digestive() , false)



  let sig = `\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp\x0e'm\x8f@\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)\xde\xca\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t`
    sig = Buffer.from(sig , 'binary')
  let sig64b = Buffer.from(Base64.encode(sig),'binary')

 let  sig64 = sig64b.toString()

 assert.deepStrictEqual(sig64b , Buffer.from('mdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ','binary') )
 assert.deepStrictEqual(sig64 , 'mdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ')

let qsig64 = '0BmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
let qsig64b = Buffer.from('0BmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ', 'binary')
let qsigB2 = '\xd0\x19\x9d#\xc3\x92BC\t\xf6\xbf\xb1\x8a\x08\xc4\x07!#"\xe6\xbb,q\xf7\x00\xe2v\xd8\xf4\n\xaaX\xcc\x86\xe8\\\x82\x1fg\x19\x17\n\x9e\xcc\xf9*\xf2\x9d\xec\xaf\xc7\xf7\xedv\xf7\xc1x!\xddC\xc6\xf2(\x12`\x90'
 
qsigB2 = Buffer.from(qsigB2 , 'binary')
// # qsig64 = '0BmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
  // # qsig64b = b'0BmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
  // # qsigB2 = (b'\xd0\x19\x9d#\xc3\x92BC\t\xf6\xbf\xb1\x8a\x08\xc4\x07!#"\xe6\xbb,q\xf7'
  // #         b'\x00\xe2v\xd8\xf4\n\xaaX\xcc\x86\xe8\\\x82\x1fg\x19\x17\n\x9e\xcc'
  // #         b'\xf9*\xf2\x9d\xec\xaf\xc7\xf7\xedv\xf7\xc1x!\xddC\xc6\xf2(\x12`\x90')



  // matter =  new Matter(sig, code=derivationCodes.allCharcodes.Ed25519_SIG)
  //   assert.deepStrictEqual(matter.raw() , sig)
  //   assert.deepStrictEqual(matter.code() , derivationCodes.allCharcodes.Ed25519_SIG)
  //   assert.deepStrictEqual(matter.qb64() , qsig64)
  //   assert.deepStrictEqual(matter.qb64b() , qsig64b)
  //   assert.deepStrictEqual(matter.qb2() , qsigB2)
  //   assert.deepStrictEqual(matter.transferable() , true)
  //   assert.deepStrictEqual(matter.digestive() , false)


    // matter =  new Matter(null, derivationCodes.allCharcodes.Ed25519N,qsig64b)
    // assert.deepStrictEqual(matter.raw() , sig)
    // assert.deepStrictEqual(matter.code() , derivationCodes.allCharcodes.Ed25519_SIG)
    // assert.deepStrictEqual(matter.qb64() , qsig64)
    // assert.deepStrictEqual(matter.qb64b() , qsig64b)
    // assert.deepStrictEqual(matter.qb2() , qsigB2)
    // assert.deepStrictEqual(matter.transferable() , true)
    // assert.deepStrictEqual(matter.digestive() , false)

    // matter =  new Matter(null, derivationCodes.allCharcodes.Ed25519N,null,qsig64)
    // assert.deepStrictEqual(matter.raw() , sig)
    // assert.deepStrictEqual(matter.code() , derivationCodes.allCharcodes.Ed25519_SIG)
    // assert.deepStrictEqual(matter.qb64() , qsig64)
    // assert.deepStrictEqual(matter.qb64b() , qsig64b)
    // assert.deepStrictEqual(matter.qb2() , qsigB2)
    // assert.deepStrictEqual(matter.transferable() , true)
    // assert.deepStrictEqual(matter.digestive() , false)



    // matter =  new Matter(null, derivationCodes.allCharcodes.Ed25519N,null,null,qsigB2)
    // assert.deepStrictEqual(matter.raw() , sig)
    // assert.deepStrictEqual(matter.code() , derivationCodes.allCharcodes.Ed25519_SIG)
    // assert.deepStrictEqual(matter.qb64() , qsig64)
    // assert.deepStrictEqual(matter.qb64b() , qsig64b)
    // assert.deepStrictEqual(matter.qb2() , qsigB2)
    // assert.deepStrictEqual(matter.transferable() , true)
    // assert.deepStrictEqual(matter.digestive() , false)
  // # matter = Matter(qb2=qsigB2)
  // # assert matter.raw == sig
  // # assert matter.code == MtrDex.Ed25519_Sig
  // # assert matter.qb64 == qsig64
  // # assert matter.qb64b == qsig64b
  // # assert matter.qb2 == qsigB2
  // # assert matter.transferable == True
  // # assert matter.digestive == False


let val = parseInt("F77F",16)
assert.equal(val,63359)

let raw = Buffer.from("\xf7\x7f",'binary')
console.log(raw.toString())
let txt = Base64.encode(raw)
assert.deepStrictEqual(txt, '938')
let qb64b = Buffer.from(derivationCodes.allCharcodes.SHORT,'binary') + txt.slice(0,txt.length)
let qb64 = qb64b.toString() 
let qb2 =  Buffer.from('3\xdd\xfc','binary')
// assert.deepEqual(Buffer.from(val.toString(),'binary') , Buffer.from('\xf7\x7f', 'binary'))

// ============= PENDING CASES ===================
  // # # test short
  // # val = int("F77F", 16)
  // # assert val == 63359
  // # raw = val.to_bytes(2, 'big')
  // # assert raw == b'\xf7\x7f'
  // # txt = encodeB64(raw)
  // # assert txt == b'938='
  // # qb64b = MtrDex.Short.encode("utf-8") + txt[:-1]
  // # assert qb64b == b'M938'
  // # qb64 = qb64b.decode("utf-8")
  // # qb2 = decodeB64(qb64b)
  // # assert qb2 == b'3\xdd\xfc'

  // ============= PENDING CASES ===================



  // matter = new Matter(raw,derivationCodes.allCharcodes.SHORT)
  // assert.deepStrictEqual(matter.raw() , raw)
  // assert.deepStrictEqual(matter.code() ,derivationCodes.allCharcodes.SHORT)
  // assert.deepStrictEqual(matter.qb64() , qb64)
  // assert.deepStrictEqual(matter.qb64b() , Buffer.from(qb64b,'binary'))
  // assert.deepStrictEqual(matter.qb2() , qb2)
  // assert.deepStrictEqual(matter.transferable() , true)
  // assert.deepStrictEqual(matter.digestive() , false)



// matter = new Matter(null,derivationCodes.allCharcodes.Ed25519N,qb64b)
// assert.deepStrictEqual(matter.raw() , raw)
// assert.deepStrictEqual(matter.code() ,derivationCodes.allCharcodes.SHORT)
// assert.deepStrictEqual(matter.qb64() , qb64)
// assert.deepStrictEqual(matter.qb64b() , Buffer.from(qb64b,'binary'))
// assert.deepStrictEqual(matter.qb2() , qb2)
// assert.deepStrictEqual(matter.transferable() , true)
// assert.deepStrictEqual(matter.digestive() , false)



//   matter = new Matter(null,derivationCodes.allCharcodes.Ed25519N,null,qb64)
// assert.deepStrictEqual(matter.raw() , raw)
// assert.deepStrictEqual(matter.code() ,derivationCodes.allCharcodes.SHORT)
// assert.deepStrictEqual(matter.qb64() , qb64)
// assert.deepStrictEqual(matter.qb64b() , Buffer.from(qb64b,'binary'))
// assert.deepStrictEqual(matter.qb2() , qb2)
// assert.deepStrictEqual(matter.transferable() , true)
// assert.deepStrictEqual(matter.digestive() , false)



  // matter = new Matter(null,derivationCodes.allCharcodes.Ed25519N,null,null,qb2)
  // assert.deepStrictEqual(matter.raw() , raw)
  // assert.deepStrictEqual(matter.code() ,derivationCodes.allCharcodes.SHORT)
  // assert.deepStrictEqual(matter.qb64() , qb64)
  // assert.deepStrictEqual(matter.qb64b() , Buffer.from(qb64b,'binary'))
  // assert.deepStrictEqual(matter.qb2() , qb2)
  // assert.deepStrictEqual(matter.transferable() , true)
  // assert.deepStrictEqual(matter.digestive() , false)


  // # # test long

   val = parseInt("F7F33F7F",16)
assert.equal(val,4159913855)

 raw = Buffer.from("\xf7\xf3?\x7f",'binary')
console.log(raw.toString())
 txt = Base64.encode(raw)
assert.deepStrictEqual(txt, '9_M_fw')
 qb64b = Buffer.from(derivationCodes.allCharcodes.Long,'binary') + txt.slice(0,txt.length) //0H9_M_fw
console.log("Value of qb64b =",qb64b)
 qb64 = qb64b.toString() 
 qb2 =  Buffer.from('\xd0\x7f\x7f3\xf7\xf0','binary')
  // # val = int("F7F33F7F", 16)
  // # assert val == 4159913855
  // # raw = val.to_bytes(4, 'big')
  // # assert raw ==b'\xf7\xf3?\x7f'
  // # txt = encodeB64(raw)
  // # assert txt == b'9_M_fw=='
  // # qb64b = MtrDex.Long.encode("utf-8") + txt[:-2]
  // # assert qb64b == b'0H9_M_fw'
  // # qb64 = qb64b.decode("utf-8")
  // # qb2 = decodeB64(qb64b)
  // # assert qb2 == b'\xd0\x7f\x7f3\xf7\xf0'


//     matter = new Matter(raw,derivationCodes.allCharcodes.Long)
//   assert.deepStrictEqual(matter.raw() , raw)
//   assert.deepStrictEqual(matter.code() ,derivationCodes.allCharcodes.Long)
//   assert.deepStrictEqual(matter.qb64() , qb64)
//   assert.deepStrictEqual(matter.qb64b() , Buffer.from(qb64b,'binary'))
//   assert.deepStrictEqual(matter.qb2() , qb2)
//   assert.deepStrictEqual(matter.transferable() , true)
//   assert.deepStrictEqual(matter.digestive() , false)




//   matter = new Matter(null,derivationCodes.allCharcodes.Ed25519N,qb64b)
// assert.deepStrictEqual(matter.raw() , raw)
// assert.deepStrictEqual(matter.code() ,derivationCodes.allCharcodes.Long)
// assert.deepStrictEqual(matter.qb64() , qb64)
// assert.deepStrictEqual(matter.qb64b() , Buffer.from(qb64b,'binary'))
// assert.deepStrictEqual(matter.qb2() , qb2)
// assert.deepStrictEqual(matter.transferable() , true)
// assert.deepStrictEqual(matter.digestive() , false)



//   matter = new Matter(null,derivationCodes.allCharcodes.Ed25519N,null,qb64)
// assert.deepStrictEqual(matter.raw() , raw)
// assert.deepStrictEqual(matter.code() ,derivationCodes.allCharcodes.Long)
// assert.deepStrictEqual(matter.qb64() , qb64)
// assert.deepStrictEqual(matter.qb64b() , Buffer.from(qb64b,'binary'))
// assert.deepStrictEqual(matter.qb2() , qb2)
// assert.deepStrictEqual(matter.transferable() , true)
// assert.deepStrictEqual(matter.digestive() , false)


 // ==================> GETTING FAILED DUE TO BASE64 ISSUE ====================


  // matter = new Matter(null,derivationCodes.allCharcodes.Ed25519N,null,null,qb2)
  // assert.deepStrictEqual(matter.raw() , raw)
  // assert.deepStrictEqual(matter.code() ,derivationCodes.allCharcodes.Long)
  // assert.deepStrictEqual(matter.qb64() , qb64)
  // assert.deepStrictEqual(matter.qb64b() , Buffer.from(qb64b,'binary'))
  // assert.deepStrictEqual(matter.qb2() , qb2)
  // assert.deepStrictEqual(matter.transferable() , true)
  // assert.deepStrictEqual(matter.digestive() , false)


 // ==================> GETTING FAILED DUE TO BASE64 ISSUE ====================



  // # matter = Matter(qb2=qb2)
  // # assert matter.raw == raw
  // # assert matter.code == MtrDex.Long
  // # assert matter.qb64 == qb64
  // # assert matter.qb64b == qb64b
  // # assert matter.qb2 == qb2
  // # assert matter.transferable == True
  // # assert matter.digestive == False



  // # # test tag as number

  val = parseInt("F89CFF",16)
  assert.equal(val,16293119)
  
   raw = Buffer.from("\xf8\x9c\xff",'binary')
  console.log(raw.toString())
   txt = Base64.encode(raw)
  assert.deepStrictEqual(txt, '-Jz_')
   qb64b = Buffer.from(derivationCodes.allCharcodes.Tag,'binary') + txt //1AAF-Jz_
  console.log("Value of qb64b *******************8",qb64b)
   qb64 = qb64b.toString() 
   qb2 =  Buffer.from('\xd4\x00\x05\xf8\x9c\xff','binary')

  // # val = int("F89CFF", 16)
  // # assert val == 16293119
  // # raw = val.to_bytes(3, 'big')
  // # assert raw == b'\xf8\x9c\xff'
  // # txt = encodeB64(raw)
  // # assert txt == b'-Jz_'
  // # qb64b = MtrDex.Tag.encode("utf-8") + txt
  // # assert qb64b ==b'1AAF-Jz_'
  // # qb64 = qb64b.decode("utf-8")
  // # qb2 = decodeB64(qb64b)
  // # assert qb2 == b'\xd4\x00\x05\xf8\x9c\xff'


      // matter = new Matter(raw,derivationCodes.allCharcodes.Tag)
  // assert.deepStrictEqual(matter.raw() , raw)
  // assert.deepStrictEqual(matter.code() ,derivationCodes.allCharcodes.Tag)
  // assert.deepStrictEqual(matter.qb64() , qb64)
  // assert.deepStrictEqual(matter.qb64b() , Buffer.from(qb64b,'binary'))
  // assert.deepStrictEqual(matter.qb2() , qb2)
  // assert.deepStrictEqual(matter.transferable() , true)
  // assert.deepStrictEqual(matter.digestive() , false)




//   matter = new Matter(null,derivationCodes.allCharcodes.Ed25519N,qb64b)
// assert.deepStrictEqual(matter.raw() , raw)
// assert.deepStrictEqual(matter.code() ,derivationCodes.allCharcodes.Tag)
// assert.deepStrictEqual(matter.qb64() , qb64)
// assert.deepStrictEqual(matter.qb64b() , Buffer.from(qb64b,'binary'))
// assert.deepStrictEqual(matter.qb2() , qb2)
// assert.deepStrictEqual(matter.transferable() , true)
// assert.deepStrictEqual(matter.digestive() , false)



//   matter = new Matter(null,derivationCodes.allCharcodes.Ed25519N,null,qb64)
// assert.deepStrictEqual(matter.raw() , raw)
// assert.deepStrictEqual(matter.code() ,derivationCodes.allCharcodes.Tag)
// assert.deepStrictEqual(matter.qb64() , qb64)
// assert.deepStrictEqual(matter.qb64b() , Buffer.from(qb64b,'binary'))
// assert.deepStrictEqual(matter.qb2() , qb2)
// assert.deepStrictEqual(matter.transferable() , true)
// assert.deepStrictEqual(matter.digestive() , false)


 // ==================> GETTING FAILED DUE TO BASE64 ISSUE ====================


  // matter = new Matter(null,derivationCodes.allCharcodes.Ed25519N,null,null,qb2)
  // assert.deepStrictEqual(matter.raw() , raw)
  // assert.deepStrictEqual(matter.code() ,derivationCodes.allCharcodes.Tag)
  // assert.deepStrictEqual(matter.qb64() , qb64)
  // assert.deepStrictEqual(matter.qb64b() , Buffer.from(qb64b,'binary'))
  // assert.deepStrictEqual(matter.qb2() , qb2)
  // assert.deepStrictEqual(matter.transferable() , true)
  // assert.deepStrictEqual(matter.digestive() , false)


 // ==================> GETTING FAILED DUE TO BASE64 ISSUE ====================


  // # matter = Matter(qb2=qb2)
  // # assert matter.raw == raw
  // # assert matter.code == MtrDex.Tag
  // # assert matter.qb64 == qb64
  // # assert matter.qb64b == qb64b
  // # assert matter.qb2 == qb2
  // # assert matter.transferable == True
  // # assert matter.digestive == False






  
   raw = Buffer.from("\x89\xca\x7f",'binary')
  console.log(raw.toString())
   txt = Buffer.from('icp_','binary')
   qb64b = Buffer.from(derivationCodes.allCharcodes.Tag,'binary') + txt //1AAF-Jz_
  console.log("Value of qb64b *******************8",qb64b)
   qb64 = qb64b.toString() 
   qb2 =  Buffer.from('\xd4\x00\x05\xf8\x9c\xff','binary')



//         matter = new Matter(raw,derivationCodes.allCharcodes.Tag)
//   assert.deepStrictEqual(matter.raw() , raw)
//   assert.deepStrictEqual(matter.code() ,derivationCodes.allCharcodes.Tag)
//   assert.deepStrictEqual(matter.qb64() , qb64)
//   assert.deepStrictEqual(matter.qb64b() , Buffer.from(qb64b,'binary'))
//   // assert.deepStrictEqual(matter.qb2() , qb2)
//   assert.deepStrictEqual(matter.transferable() , true)
//   assert.deepStrictEqual(matter.digestive() , false)




//   matter = new Matter(null,derivationCodes.allCharcodes.Ed25519N,qb64b)
// assert.deepStrictEqual(matter.raw() , raw)
// assert.deepStrictEqual(matter.code() ,derivationCodes.allCharcodes.Tag)
// assert.deepStrictEqual(matter.qb64() , qb64)
// assert.deepStrictEqual(matter.qb64b() , Buffer.from(qb64b,'binary'))
// // assert.deepStrictEqual(matter.qb2() , qb2)
// assert.deepStrictEqual(matter.transferable() , true)
// assert.deepStrictEqual(matter.digestive() , false)



//   matter = new Matter(null,derivationCodes.allCharcodes.Ed25519N,null,qb64)
// assert.deepStrictEqual(matter.raw() , raw)
// assert.deepStrictEqual(matter.code() ,derivationCodes.allCharcodes.Tag)
// assert.deepStrictEqual(matter.qb64() , qb64)
// assert.deepStrictEqual(matter.qb64b() , Buffer.from(qb64b,'binary'))
// // assert.deepStrictEqual(matter.qb2() , qb2)
// assert.deepStrictEqual(matter.transferable() , true)
// assert.deepStrictEqual(matter.digestive() , false)


 // ==================> GETTING FAILED DUE TO BASE64 ISSUE ====================


  // matter = new Matter(null,derivationCodes.allCharcodes.Ed25519N,null,null,qb2)
  // assert.deepStrictEqual(matter.raw() , raw)
  // assert.deepStrictEqual(matter.code() ,derivationCodes.allCharcodes.Tag)
  // assert.deepStrictEqual(matter.qb64() , qb64)
  // assert.deepStrictEqual(matter.qb64b() , Buffer.from(qb64b,'binary'))
  // assert.deepStrictEqual(matter.qb2() , qb2)
  // assert.deepStrictEqual(matter.transferable() , true)
  // assert.deepStrictEqual(matter.digestive() , false)


 // ==================> GETTING FAILED DUE TO BASE64 ISSUE ====================


//  txt = b'icp_'
//  raw = decodeB64(txt)
//  assert raw == b'\x89\xca\x7f'
//  val = int.from_bytes(raw, 'big')
//  assert val == 9030271
//  qb64b = MtrDex.Tag.encode("utf-8") + txt
//  assert qb64b ==b'1AAFicp_'
//  qb64 = qb64b.decode("utf-8")
//  qb2 = decodeB64(qb64b)
//  assert qb2 == b'\xd4\x00\x05\x89\xca\x7f'


 txt = Buffer.from('icp_', 'binary')
 raw == Buffer.from('\x89\xca\x7f','binary')
 val = bignum.fromBuffer(raw)
 val = BigInt(val.toString())
 console.log("val =========>",val.toString())
 qb64b = Buffer.from(derivationCodes.allCharcodes.Tag,'binary') + txt //1AAF-Jz_
 console.log("Value of qb64b *******************8",qb64b)
  qb64 = qb64b.toString() 
  qb2 =  Buffer.from('\xd4\x00\x05\x89\xca\x7f','binary')
  // # # test tag as chars
  // # txt = b'icp_'
  // # raw = decodeB64(txt)
  // # assert raw == b'\x89\xca\x7f'
  // # val = int.from_bytes(raw, 'big')
  // # assert val == 9030271
  // # qb64b = MtrDex.Tag.encode("utf-8") + txt
  // # assert qb64b ==b'1AAFicp_'
  // # qb64 = qb64b.decode("utf-8")
  // # qb2 = decodeB64(qb64b)
  // # assert qb2 == b'\xd4\x00\x05\x89\xca\x7f'

  // # matter = Matter(raw=raw, code=MtrDex.Tag)
  // # assert matter.raw == raw
  // # assert matter.code == MtrDex.Tag
  // # assert matter.qb64 == qb64
  // # assert matter.qb64b == qb64b
  // # assert matter.qb2 == qb2
  // # assert matter.transferable == True
  // # assert matter.digestive == False

  // # matter = Matter(qb64b=qb64b)
  // # assert matter.raw == raw
  // # assert matter.code == MtrDex.Tag
  // # assert matter.qb64 == qb64
  // # assert matter.qb64b == qb64b
  // # assert matter.qb2 == qb2
  // # assert matter.transferable == True
  // # assert matter.digestive == False

  // # matter = Matter(qb64=qb64)
  // # assert matter.raw == raw
  // # assert matter.code == MtrDex.Tag
  // # assert matter.qb64 == qb64
  // # assert matter.qb64b == qb64b
  // # assert matter.qb2 == qb2
  // # assert matter.transferable == True
  // # assert matter.digestive == False

  // # matter = Matter(qb2=qb2)
  // # assert matter.raw == raw
  // # assert matter.code == MtrDex.Tag
  // # assert matter.qb64 == qb64
  // # assert matter.qb64b == qb64b
  // # assert matter.qb2 == qb2
  // # assert matter.transferable == True
  // # assert matter.digestive == False

  // # # Test ._bexfil

  matter = new Matter(null,derivationCodes.allCharcodes.Ed25519N,null,prefix)

  raw = matter.raw()
  code = matter.code()
  qb2 = matter.qb2()

  matter.bexfil(qb2)
  // assert.deepStrictEqual(matter.raw() , raw)
  assert.deepStrictEqual(matter.code() , code)
  assert.deepStrictEqual(matter.qb64() , prefix)
  assert.deepStrictEqual(matter.qb2() , qb2)
  // # matter = Matter(qb64=prefix)  #
  // # raw = matter.raw
  // # code = matter.code
  // # qb2 = matter.qb2
  // # matter._bexfil(qb2)
  // # assert matter.raw == raw
  // # assert matter.code == code
  // # assert matter.qb64 == prefix
  // # assert matter.qb2 == qb2


  //   assert.deepStrictEqual(matter.raw() , raw)
//   assert.deepStrictEqual(matter.code() ,derivationCodes.allCharcodes.Tag)
//   assert.deepStrictEqual(matter.qb64() , qb64)
//   assert.deepStrictEqual(matter.qb64b() , Buffer.from(qb64b,'binary'))
//   // assert.deepStrictEqual(matter.qb2() , qb2)
//   assert.deepStrictEqual(matter.transferable() , true)
//   assert.deepStrictEqual(matter.digestive() , false)

  // # # Test ._binfil
  // # test = matter._binfil()
  // # assert test == qb2


//  """ Done Test """
}


 function test_seqner(){
/**
 *     Test Seqner sequence number subclass of CryMat
 */

  // const  seqner =  new Seqner(null, null, null, null, derivationCodes.twoCharCode.SALT_128)  //  defaults to zero

  // console.log("seqner ==================>",seqner)
  //   assert.deepStrictEqual(seqner.raw()  , Buffer.from('\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00','binary'))

  //   assert.deepStrictEqual( seqner.code() , derivationCodes.twoCharCode.SALT_128)
  //   // assert.deepStrictEqual(number.sn() , 0)
  //   assert.deepStrictEqual(seqner.snh() , '0') 
  //   assert.deepStrictEqual(seqner.qb64() , '0AAAAAAAAAAAAAAAAAAAAAAA')
  //   assert.deepStrictEqual(seqner.qb64b() , Buffer.from('0AAAAAAAAAAAAAAAAAAAAAAA','binary')) 
  //   assert.deepStrictEqual(seqner.qb2() , Buffer.from('\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00','binary')) 

   let snraw = Buffer.from('\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00','binary')
   let  snqb64b = Buffer.from('0AAAAAAAAAAAAAAAAAAAAAAA', 'binary')
   let  snqb64 = '0AAAAAAAAAAAAAAAAAAAAAAA'
  let  snqb2 = Buffer.from('\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00','binary')
console.log("snqb2 ===================>",snqb2)
    // with pytest.raises(RawMaterialError):
    //     number = Seqner(raw=b'')
  //  const  seqner =  new Seqner(null, null, null, null, derivationCodes.twoCharCode.SALT_128)
   let number = new Seqner(null, snqb64b, null, null, derivationCodes.twoCharCode.SALT_128);
    // assert.deepStrictEqual(number.raw() , snraw)
    // assert.deepStrictEqual(number.code() , derivationCodes.twoCharCode.SALT_128)
    // assert.deepStrictEqual(number.sn() , 0)
    // assert.deepStrictEqual(number.snh() , '0')
    // assert.deepStrictEqual(number.qb64() , snqb64)
    // assert.deepStrictEqual(number.qb64b() , snqb64b)
    // assert.deepStrictEqual(number.qb2() , snqb2)



    // number = new Seqner(null, null , snqb64, null, derivationCodes.twoCharCode.SALT_128);
    // assert.deepStrictEqual(number.raw() , snraw)
    // assert.deepStrictEqual(number.code() , derivationCodes.twoCharCode.SALT_128)
    // assert.deepStrictEqual(number.sn() , 0)
    // assert.deepStrictEqual(number.snh() , '0')
    // assert.deepStrictEqual(number.qb64() , snqb64)
    // assert.deepStrictEqual(number.qb64b() , snqb64b)
    // assert.deepStrictEqual(number.qb2() , snqb2)

    number = new Seqner(null, null , null, snqb2, derivationCodes.twoCharCode.SALT_128);
    assert.deepStrictEqual(number.raw() , snraw)
    assert.deepStrictEqual(number.code() , derivationCodes.twoCharCode.SALT_128)
    assert.deepStrictEqual(number.sn() , 0)
    assert.deepStrictEqual(number.snh() , '0')
    assert.deepStrictEqual(number.qb64() , snqb64)
    assert.deepStrictEqual(number.qb64b() , snqb64b)
    assert.deepStrictEqual(number.qb2() , snqb2)


    // number = Seqner(qb2=snqb2)
    // assert number.raw == snraw
    // assert number.code == MtrDex.Salt_128
    // assert number.sn == 0
    // assert number.snh == '0'
    // assert number.qb64 == snqb64
    // assert number.qb64b == snqb64b
    // assert number.qb2 == snqb2

    //  number = new Seqner(snraw, null , null, null, derivationCodes.twoCharCode.SALT_128);
    // assert.deepStrictEqual(number.raw() , snraw)
    // assert.deepStrictEqual(number.code() , derivationCodes.twoCharCode.SALT_128)
    // assert.deepStrictEqual(number.sn() , 0)
    // assert.deepStrictEqual(number.snh() , 0)
    // assert.deepStrictEqual(number.qb64() , snqb64)
    // assert.deepStrictEqual(number.qb64b() , snqb64b)
    // assert.deepStrictEqual(number.qb2() , snqb2)




    // # test priority lower for sn and snh


    // number = new Seqner(null, snqb64b , null, null, derivationCodes.twoCharCode.SALT_128, 5,`a`);
    // assert.deepStrictEqual(number.raw() , snraw)
    // assert.deepStrictEqual(number.code() , derivationCodes.twoCharCode.SALT_128)
    // assert.deepStrictEqual(number.sn() , 0)
    // assert.deepStrictEqual(number.snh() , '0')
    // assert.deepStrictEqual(number.qb64() , snqb64)
    // assert.deepStrictEqual(number.qb64b() , snqb64b)
    // assert.deepStrictEqual(number.qb2() , snqb2)
    


    // number = new Seqner(null, null , snqb64, null, derivationCodes.twoCharCode.SALT_128, 5,`a`);
    // assert.deepStrictEqual(number.raw() , snraw)
    // assert.deepStrictEqual(number.code() , derivationCodes.twoCharCode.SALT_128)
    // assert.deepStrictEqual(number.sn() , 0)
    // assert.deepStrictEqual(number.snh() , '0')
    // assert.deepStrictEqual(number.qb64() , snqb64)
    // assert.deepStrictEqual(number.qb64b() , snqb64b)
    // assert.deepStrictEqual(number.qb2() , snqb2)


    // number = new Seqner(null, null , null , snqb2, derivationCodes.twoCharCode.SALT_128, 5,`a`);
    // assert.deepStrictEqual(number.raw() , snraw)
    // assert.deepStrictEqual(number.code() , derivationCodes.twoCharCode.SALT_128)
    // assert.deepStrictEqual(number.sn() , 0)
    // assert.deepStrictEqual(number.snh() , '0')
    // assert.deepStrictEqual(number.qb64() , snqb64)
    // assert.deepStrictEqual(number.qb64b() , snqb64b)
    // assert.deepStrictEqual(number.qb2() , snqb2)

    // number = Seqner(qb2=snqb2, sn=5, snh='a')
    // assert number.raw == snraw
    // assert number.code == MtrDex.Salt_128
    // assert number.sn == 0
    // assert number.snh == '0'
    // assert number.qb64 == snqb64
    // assert number.qb64b == snqb64b
    // assert number.qb2 == snqb2


    // number = new Seqner(snraw, null , null , null, derivationCodes.twoCharCode.SALT_128, 5,`a`);
    // assert.deepStrictEqual(number.raw() , snraw)
    // assert.deepStrictEqual(number.code() , derivationCodes.twoCharCode.SALT_128)
    // assert.deepStrictEqual(number.sn() , 0)
    // assert.deepStrictEqual(number.snh() , '0')
    // assert.deepStrictEqual(number.qb64() , snqb64)
    // assert.deepStrictEqual(number.qb64b() , snqb64b)
    // assert.deepStrictEqual(number.qb2() , snqb2)
    

    // number = new Seqner(null, null , null , null, derivationCodes.twoCharCode.SALT_128, 5,`a`);
    // assert.deepStrictEqual(number.raw() , Buffer.from('\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05', 'binary'))
    // assert.deepStrictEqual(number.code() , derivationCodes.twoCharCode.SALT_128)
    // assert.deepStrictEqual(number.sn() , 5)
    // assert.deepStrictEqual(number.snh() , '5')
    // assert.deepStrictEqual(number.qb64() , '0AAAAAAAAAAAAAAAAAAAAABQ')
    // assert.deepStrictEqual(number.qb64b() , Buffer.from('0AAAAAAAAAAAAAAAAAAAAABQ','binary'))
    // assert.deepStrictEqual(number.qb2() , Buffer.from('\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00P','binary'))


    // number = new Seqner(null, null , null , null, derivationCodes.twoCharCode.SALT_128, null,`a`);
    // assert.deepStrictEqual(number.raw() , Buffer.from('\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\n', 'binary'))
    // assert.deepStrictEqual(number.code() , derivationCodes.twoCharCode.SALT_128)
    // assert.deepStrictEqual(number.sn() , 10)
    // assert.deepStrictEqual(number.snh() , 'a')
    // assert.deepStrictEqual(number.qb64() , '0AAAAAAAAAAAAAAAAAAAAACg')
    // assert.deepStrictEqual(number.qb64b() , Buffer.from('0AAAAAAAAAAAAAAAAAAAAACg','binary'))
    // assert.deepStrictEqual(number.qb2() , Buffer.from('\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa0','binary'))



    // # More tests

     snraw = Buffer.from('\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05','binary')
      snqb64b = Buffer.from('0AAAAAAAAAAAAAAAAAAAAABQ', 'binary')
      snqb64 = '0AAAAAAAAAAAAAAAAAAAAABQ'
     snqb2 = Buffer.from('\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00P','binary')


    //  number = new Seqner(null, null , snqb64 , null, derivationCodes.twoCharCode.SALT_128);
    //  assert.deepStrictEqual(number.raw() , snraw)
    //  assert.deepStrictEqual(number.code() , derivationCodes.twoCharCode.SALT_128)
    //  assert.deepStrictEqual(number.sn() , 5)
    //  assert.deepStrictEqual(number.snh() , '5')
    //  assert.deepStrictEqual(number.qb64() , snqb64)
    //  assert.deepStrictEqual(number.qb64b() , snqb64b)
    //  assert.deepStrictEqual(number.qb2() , snqb2)

    //  number = new Seqner(null, snqb64b , null , null, derivationCodes.twoCharCode.SALT_128);
    //  assert.deepStrictEqual(number.raw() , snraw)
    //  assert.deepStrictEqual(number.code() , derivationCodes.twoCharCode.SALT_128)
    //  assert.deepStrictEqual(number.sn() , 5)
    //  assert.deepStrictEqual(number.snh() , '5')
    //  assert.deepStrictEqual(number.qb64() , snqb64)
    //  assert.deepStrictEqual(number.qb64b() , snqb64b)
    //  assert.deepStrictEqual(number.qb2() , snqb2)


    //  number = new Seqner(null, null , null , snqb2, derivationCodes.twoCharCode.SALT_128,5);
    //  assert.deepStrictEqual(number.raw() , snraw)
    //  assert.deepStrictEqual(number.code() , derivationCodes.twoCharCode.SALT_128)
    //  assert.deepStrictEqual(number.sn() , 5)
    //  assert.deepStrictEqual(number.snh() , '5')
    //  assert.deepStrictEqual(number.qb64() , snqb64)
    //  assert.deepStrictEqual(number.qb64b() , snqb64b)
    //  assert.deepStrictEqual(number.qb2() , snqb2)

    // number = Seqner(qb2=snqb2, sn=5)
    // assert number.raw == snraw
    // assert number.code == MtrDex.Salt_128
    // assert number.sn == 5
    // assert number.snh == '5'
    // assert number.qb64 == snqb64
    // assert number.qb64b == snqb64b
    // assert number.qb2 == snqb2


     number = new Seqner(snraw, null , null , null, derivationCodes.twoCharCode.SALT_128,5);
     assert.deepStrictEqual(number.raw() , snraw)
     assert.deepStrictEqual(number.code() , derivationCodes.twoCharCode.SALT_128)
     assert.deepStrictEqual(number.sn() , 5)
     assert.deepStrictEqual(number.snh() , '5')
     assert.deepStrictEqual(number.qb64() , snqb64)
     assert.deepStrictEqual(number.qb64b() , snqb64b)
     assert.deepStrictEqual(number.qb2() , snqb2)
    

    // """ Done Test """

}

function test_dater(){

let dater = new Dater(raw=null, qb64b=null, qb64=null, qb2=null, code=derivationCodes.allCharcodes.SALT_128, dts=null);


assert.deepStrictEqual(dater.code() , derivationCodes.allCharcodes.DateTime)
assert.deepStrictEqual((dater.code()).length , 24)
assert.deepStrictEqual((dater.qb64()).length , 36)
assert.deepStrictEqual((dater.qb2()).length , 27)
assert.deepStrictEqual((ater.dts()).length , 32)

    // dts1 = '2020-08-22T17:50:09.988921+00:00'
    // dts1b = b'2020-08-22T17:50:09.988921+00:00'
    // dt1raw = b'\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdbZt\xd1\xcd4'
    // dt1qb64 = '1AAG2020-08-22T17c50c09d988921p00c00'
    // dt1qb64b = b'1AAG2020-08-22T17c50c09d988921p00c00'
    // dt1qb2 = b'\xd4\x00\x06\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdbZt\xd1\xcd4'

    // dater = Dater(dts=dts1)
    // assert dater.raw == b'\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdbZt\xd1\xcd4'
    // assert dater.code == MtrDex.DateTime
    // assert dater.dts == dts1
    // assert dater.raw == dt1raw
    // assert dater.qb64 == dt1qb64
    // assert dater.qb64b == dt1qb64b
    // assert dater.qb2 == dt1qb2

    // dater = Dater(dts=dts1b)
    // assert dater.raw == b'\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdbZt\xd1\xcd4'
    // assert dater.code == MtrDex.DateTime
    // assert dater.dts == dts1
    // assert dater.raw == dt1raw
    // assert dater.qb64 == dt1qb64
    // assert dater.qb64b == dt1qb64b
    // assert dater.qb2 == dt1qb2

    // dts2 = '2020-08-22T17:50:09.988921-01:00'
    // dts2b = b'2020-08-22T17:50:09.988921-01:00'
    // dt2raw = b'\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdb_\xb4\xd5\xcd4'
    // dt2qb64 = '1AAG2020-08-22T17c50c09d988921-01c00'
    // dt2qb64b = b'1AAG2020-08-22T17c50c09d988921-01c00'
    // dt2qb2 = b'\xd4\x00\x06\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdb_\xb4\xd5\xcd4'

    // dater = Dater(dts=dts2)
    // assert dater.code == MtrDex.DateTime
    // assert dater.dts == dts2
    // assert dater.raw == dt2raw
    // assert dater.qb64 == dt2qb64
    // assert dater.qb64b == dt2qb64b
    // assert dater.qb2 == dt2qb2

    // dater = Dater(dts=dts2b)
    // assert dater.code == MtrDex.DateTime
    // assert dater.dts == dts2
    // assert dater.raw == dt2raw
    // assert dater.qb64 == dt2qb64
    // assert dater.qb64b == dt2qb64b
    // assert dater.qb2 == dt2qb2

    // dater = Dater(raw=dt1raw, code=MtrDex.DateTime)
    // assert dater.raw == b'\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdbZt\xd1\xcd4'
    // assert dater.code == MtrDex.DateTime
    // assert dater.dts == dts1
    // assert dater.raw == dt1raw
    // assert dater.qb64 == dt1qb64
    // assert dater.qb64b == dt1qb64b
    // assert dater.qb2 == dt1qb2

    // dater = Dater(qb64=dt1qb64)
    // assert dater.raw == b'\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdbZt\xd1\xcd4'
    // assert dater.code == MtrDex.DateTime
    // assert dater.dts == dts1
    // assert dater.raw == dt1raw
    // assert dater.qb64 == dt1qb64
    // assert dater.qb64b == dt1qb64b
    // assert dater.qb2 == dt1qb2

    // dater = Dater(qb64b=dt1qb64b)
    // assert dater.raw == b'\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdbZt\xd1\xcd4'
    // assert dater.code == MtrDex.DateTime
    // assert dater.dts == dts1
    // assert dater.raw == dt1raw
    // assert dater.qb64 == dt1qb64
    // assert dater.qb64b == dt1qb64b
    // assert dater.qb2 == dt1qb2

    // dater = Dater(qb2=dt1qb2)
    // assert dater.raw == b'\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdbZt\xd1\xcd4'
    // assert dater.code == MtrDex.DateTime
    // assert dater.dts == dts1
    // assert dater.raw == dt1raw
    // assert dater.qb64 == dt1qb64
    // assert dater.qb64b == dt1qb64b
    // assert dater.qb2 == dt1qb2

    // """ Done Test """
}

async function test_cigar() {
  // """
  // Test Cigar subclass of CryMat
  // """
  // with pytest.raises(EmptyMaterialError):
  //     cigar = Cigar()
  await libsodium.ready;
 let qsig64 = '0BmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
// raw = null, code = allCharcodes.Ed25519N, qb64b = null, qb64 = null, qb2 = null
  let kwa = [null, derivationCodes.allCharcodes.Ed25519N , null, qsig64] 
  let cigar = new Cigar(null, ...kwa)

  assert.deepStrictEqual(cigar.code() , derivationCodes.twoCharCode.Ed25519_SIG) 
  assert.deepStrictEqual(cigar.qb64() , qsig64) 
  assert.deepStrictEqual(cigar.verfer() , null)  

   let response  = libsodium.crypto_sign_keypair();
   console.log("response =========>",response.publicKey)
 let verfer =  new Verfer(Buffer.from(response.publicKey, 'binary'))
 cigar.setVerfer(verfer)
  assert.deepStrictEqual(cigar.verfer() ,verfer) 
  

  cigar = new Cigar(verfer, ...kwa)
  assert.deepStrictEqual(cigar.verfer() , verfer) 
//  """ Done Test """
}


async function test_salter(){

  let salter = new  Salter(null, derivationCodes.allCharcodes.SALT_128)  //# defaults to CryTwoDex.Salt_128


  assert.deepStrictEqual(salter.code() ,  derivationCodes.twoCharCode.SALT_128);
  assert.deepStrictEqual((salter.raw()).length ,  Matter.rawSize(salter.code()));
  assert.deepStrictEqual((salter.raw()).length ,  16);

  // let   raw = Buffer.from('0123456789abcdef', 'binary')

  //  let salter = new Salter(raw);
  //   assert.deepStrictEqual(salter.raw() , raw);
  //   assert.deepStrictEqual(salter.qb64() , '0AMDEyMzQ1Njc4OWFiY2RlZg');

  // let  signer = salter.signer("01", derivationCodes.allCharcodes.Ed25519_Seed,true, true)   //# defaults to Ed25519
  //   assert.deepStrictEqual(signer.code() ,derivationCodes.oneCharCode.Ed25519_Seed);
  //   assert.deepStrictEqual((salter.raw()).length , Matter.rawSize(salter.code()));
  //   assert.deepStrictEqual(signer.verfer.code() ,derivationCodes.oneCharCode.Ed25519);
  //   assert.deepStrictEqual((signer.verfer.raw()).length ,Matter.rawSize(signer.verfer.code()));
  //   assert.deepStrictEqual(salter.qb64() , 'Aw-yoFnFZ21ikGGtacpiK3AVrvuz3TZD6dfew9POqzRE');
  //   assert.deepStrictEqual(signer.verfer.qb64() , 'DVgXBkk4w3LcWScQIvy1RpBlEFTJD3EK_oXxyQb5QKsI');
  //   signer = salter.signer("01") // # defaults to Ed25519 temp = False level="low"

  //   assert.deepStrictEqual(signer.code() ,derivationCodes.oneCharCode.Ed25519_Seed);
  //   assert.deepStrictEqual((salter.raw()).length , Matter.rawSize(salter.code()));
  //   assert.deepStrictEqual(signer.verfer.code() ,derivationCodes.oneCharCode.Ed25519);
  //   assert.deepStrictEqual(salter.qb64() , 'ASSpCI1N7FYH19MumAmn-Vdbre0WVP5jT-aBDDDij50I');
  //   assert.deepStrictEqual(signer.verfer.qb64() , 'D8kbIf0fUz9JRJ_XxHNfw6p3KHETJkmkqbkSbQ-emxZ0');

  //   let kwa = [null, '0AMDEyMzQ1Njc4OWFiY2RlZg']
  //   salter =  new Salter(null ,derivationCodes.twoCharCode.SALT_128, ...kwa);
  //   assert.deepStrictEqual(salter.raw() , raw) 
  //   assert.deepStrictEqual(salter.qb64() , '0AMDEyMzQ1Njc4OWFiY2RlZg')


    // with pytest.raises(ShortageError):
    //     salter = Salter(qb64='')

}


async function test_generatesigners(){

}
//test_verfer()
//test_signer()
test_seqner()
// test_dater()
// test_cigar()
// test_nexter();
// test_matter();
// test_crycounter();
// tecrycounter()
// test_sigmat();
// test_prefixer()
// test_diger();
// test_serder()
// test_salter()
