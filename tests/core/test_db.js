const assert = require('assert').strict;
const lmdb = require('node-lmdb');
const path = require('path');
const fs = require('fs-extra')

const { pad } = require('../../src/keri/db/util');
const { snKey, splitKey, dgkey, Databaser, onKey, dtKey, splitKeyON, splitKeyDT,lmdber } = require('../../src/keri/db/database');
const {LMDBer, openLmbd} = require('../../src/keri/db/lmdb') 
const { versify, Serials } = require('../../src/keri/core/core');
const {
  openDatabaser,
  openLogger,
  Logger,
} = require('../../src/keri/db/logger');

function test_opendatabaser() {
  const db = new Databaser();
  assert.deepStrictEqual(db, new Databaser());
  assert.equal(db.name, 'main');
  assert.deepStrictEqual(db.env, new lmdb.Env());
  /// home/shivam/.keri/db


  // Test key utility functions

  // Bytes
  const pre = Buffer.from('BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc', 'binary');
  const dig = Buffer.from('EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4', 'binary');
  const sn = 3;
  const paddedSN = pad(sn, 32);
  const dts = Buffer.from('2021-02-13T19:16:50.750302+00:00', 'binary');

  assert.deepStrictEqual(
    dgkey('BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc', 'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'),
    Buffer.from(
      'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc.EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'
    )
  );

  assert.deepStrictEqual(
    onKey(pre, sn),
    Buffer.from(
      'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc.00000000000000000000000000000003'
    )
  );

  assert.deepStrictEqual(
    dtKey(pre, dts),
    Buffer.from(
      'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc|2021-02-13T19:16:50.750302+00:00'
    )
  );

  assert.deepStrictEqual(
    snKey(pre, sn),
    Buffer.from(
      `BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc.${paddedSN}`
    )
  );

  assert.deepStrictEqual(
    splitKey(snKey(pre, sn)), ['BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc', paddedSN]
  );

  assert.deepStrictEqual(
    splitKeyON(snKey(pre, sn)), ['BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc', sn]
  )

  assert.deepStrictEqual(
    splitKeyDT(dtKey(pre, dts)), ['BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc', '2021-02-13T19:16:50.750302+00:00']
  )

  db.clearDirPath();
  assert.deepStrictEqual(fs.existsSync(db.path), false);

  const dberGen = openLogger('test', null);
  const dberVal = dberGen.next().value;
  let dbi = Buffer.from('Test1', 'binary');

  let key = Buffer.from('omega4', 'binary');
  let val = Buffer.from('Abcd', 'binary');

  const vals = [
    Buffer.from('z', 'binary'),
    Buffer.from('m', 'binary'),
    Buffer.from('x', 'binary'),
    Buffer.from('a', 'binary'),
  ];
  //

  dbi = dberVal.env.openDbi({
    name: 'test_db',
    create: true,
  });

  // assert.equal(dberVal.getVal(dbi, key), false);
  // assert.equal(dberVal.delVal(dbi, key), false);
  // assert.deepStrictEqual(dberVal.putVal(dbi, key, val), true);
  // assert.equal(dberVal.putVal(dbi, key, val), true);
  // assert.deepStrictEqual(dberVal.setVal(dbi, key, val), true);
  // assert.equal((dberVal.getVal(dbi, key)).toString(), val.toString());
  // assert.equal(dberVal.delVal(dbi, key), true);
  // assert.equal(dberVal.getVal(dbi, key), null);

  // assert.deepStrictEqual(dberVal.getVals(dbi, key), []);
  // assert.deepStrictEqual(dberVal.delVals(dbi, key), false);
  // assert.deepStrictEqual(dberVal.cntVals(dbi, key), 0);

  // assert.deepStrictEqual(dberVal.putVals(dbi, key, vals), true); // [Buffer.from('a','binary'),Buffer.from('m','binary'),Buffer.from('x','binary'),Buffer.from('z','binary')]
  // console.log('dberVal.getVals(db, key) -====================>', (dberVal.getVals(dbi, key)).toString());
  // assert.deepStrictEqual(dberVal.getVals(dbi, key), [Buffer.from('a', 'binary'), Buffer.from('m', 'binary'), Buffer.from('x', 'binary'), Buffer.from('z', 'binary')]);

  // assert.deepStrictEqual(dberVal.cntVals(dbi, key), 4);
  // assert.deepStrictEqual(dberVal.putVals(dbi, key, [Buffer.from('a', 'binary')]), true);
  // assert.deepStrictEqual(dberVal.putVals(dbi, key, [Buffer.from('b', 'binary')]), true);
  // assert.deepStrictEqual(dberVal.getVals(dbi, key), [Buffer.from('a', 'binary'), Buffer.from('b', 'binary'),
  //   Buffer.from('m', 'binary'), Buffer.from('x', 'binary'), Buffer.from('z', 'binary')]);

  // assert.deepStrictEqual(dberVal.delVals(dbi, key), true);
  // assert.deepStrictEqual(dberVal.getVals(dbi, key), false);
  //   ============= PENDING =============
  //   assert [val for val in dber.getValsIter(db, key)] == [b'a', b'b', b'm', b'x', b'z']
  //   ================ PENDING

  //     #     # test IoVals insertion order dup methods.  dup vals are insertion order
  //       #     key = b'A'
  //       #     vals = [b'z', b'm', b'x', b'a']
  //       #     db = dber.env.open_db(key=b'peep.', dupsort=True)

  dbi = Buffer.from('peep.', 'binary');

  console.log('dber --------------------->', dberVal.env);
  key = Buffer.from('A', 'binary');
  val = Buffer.from('Abcd', 'binary');

  // assert.deepStrictEqual(dberVal.getIOValues(dbi, key), false);
  // assert.deepStrictEqual(dberVal.getIOValsLast(dbi, key), false);
  // assert.deepStrictEqual(dberVal.cntIoVals(dbi, key), 0);
  // assert.deepStrictEqual(dberVal.delIoVals(dbi, key), false);
  // assert.deepStrictEqual(dberVal.putIOVals(dbi, key, vals), true);
  // assert.deepStrictEqual(dberVal.getIOValues(dbi, key), vals); // # preserved insertion order
  // assert.deepStrictEqual(dberVal.cntIoVals(dbi, key), 4);
  // assert.deepStrictEqual(dberVal.getIOValsLast(dbi, key), vals[vals.length - 1]);
  // assert.deepStrictEqual(dberVal.putIOVals(dbi, key, [Buffer.from('a', 'binary')]), false); // # duplicate this will work in one shot testing
  // assert.deepStrictEqual(dberVal.getIOValues(dbi, key), vals);
  // assert.deepStrictEqual(dberVal.addIOVal(dbi, key, [Buffer.from('a', 'binary')]), true);
  // assert.deepStrictEqual(dberVal.addIOVal(dbi, key, [Buffer.from('b', 'binary')]), false); // this will work in one shot testin
  // assert.deepStrictEqual(dberVal.getIOValues(dbi, key), vals);
  // assert.deepStrictEqual(dberVal.delIoVals(dbi, key), true);

  //  #     assert dber.delIoVals(db, key) == True

  // #     # Test getIoValsAllPreIter(self, db, pre)

  // sn = 0;
  // key = snKey(pre, sn);
  // assert.deepStrictEqual(dberVal.addIOVal(dbi, key, [Buffer.from('gamma', 'binary')]), true);
  // assert.deepStrictEqual(dberVal.addIOVal(dbi, key, [Buffer.from('beta', 'binary')]), true);

  // const vals1 = [Buffer.from('mary', 'binary'), Buffer.from('peter', 'binary'), Buffer.from('john', 'binary'), Buffer.from('paul', 'binary')];
  // sn += 1;
  // key = snKey(pre, sn);
  // assert.deepStrictEqual(dberVal.putIOVals(dbi, key, vals1), true);

  // sn += 1;
  // key = snKey(pre, sn);
  // assert.deepStrictEqual(dberVal.putIOVals(dbi, key, vals1), true);

  //   *********************** THIS IS PENDING ********************************************
  //    #     vals = [bytes(val) for val in dber.getIoValsAllPreIter(db, pre)]
  //    #     allvals = vals0 + vals1 + vals2
  //    #     assert vals == allvals
  //   *********************** THIS IS PENDING ********************************************

  // #     # Test getIoValsLastAllPreIter(self, db, pre)

  // pre = Buffer.from('B4ejWzwQPYGGwTmuupUhPx5_yZ-Wk1xEHHzq7K0gzhcc', 'binary');
  // sn = 0;
  // key = snKey(pre, sn);
  // assert.deepStrictEqual(dberVal.addIOVal(dbi, key, [Buffer.from('gamma', 'binary')]), true);

  // #     vals2 = [b'dog', b'cat', b'bird']
  // #     sn += 1
  // #     key = snKey(pre, sn)
  // #     assert dber.putIoVals(db, key, vals2) == True

  // #     vals = [bytes(val) for val in dber.getIoValsLastAllPreIter(db, pre)]
  // #     lastvals = [vals0[-1], vals1[-1], vals2[-1]]
  // #     assert vals == lastvals

  // #     # Test getIoValsAnyPreIter(self, db, pre)
  // #     pre = b'BQPYGGwTmuupUhPx5_yZ-Wk1x4ejWzwEHHzq7K0gzhcc'
  // #     vals0 = [b'gamma', b'beta']
  // #     sn = 1  # not start at zero
  // #     key = snKey(pre, sn)
  // #     assert dber.addIoVal(db, key, vals0[0]) == True
  // #     assert dber.addIoVal(db, key, vals0[1]) == True

  // #     vals1 = [b'mary', b'peter', b'john', b'paul']
  // #     sn += 1
  // #     key = snKey(pre, sn)
  // #     assert dber.putIoVals(db, key, vals1) == True

  // #     vals2 = [b'dog', b'cat', b'bird']
  // #     sn += 2  # gap
  // #     key = snKey(pre, sn)
  // #     assert dber.putIoVals(db, key, vals2) == True

  // #     vals = [bytes(val) for val in dber.getIoValsAnyPreIter(db, pre)]
  // #     allvals = vals0 + vals1 + vals2
  // #     assert vals == allvals

  //  # assert not os.path.exists(dber.path)
}

 function test_lmdber(){

//   let database = new LMDBer();
//   console.log("Hello Database is = ",database.path)
//   assert.deepStrictEqual(database.name, 'main')
//   assert.deepStrictEqual(database.temp, true)
//   //assert.deepStrictEqual(fs.path.endswith, 'keri/db')

//  if(!fs.pathExistsSync(database.path)){
//    throw new Error(`Path not found! ${database.path}`);
//  }

//  let pre = Buffer.from('BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc', 'binary')
//  let dig = Buffer.from('EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4', 'binary')
//  let sn = 3
//  const paddedSN = pad(sn, 32);

//  assert.deepStrictEqual(snKey(pre, sn),
//  Buffer.from(
//    `BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc.${paddedSN}`
//  ))

//  assert.deepStrictEqual(
//   dgkey(pre, dig),
//   Buffer.from(
//     'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc.EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'
//   )
// );


const dberGen =   openLmbd('test1010', null);
const dberVal = dberGen.next().value;
//let dbi = Buffer.from('beep.', 'binary');
console.log("Value of dberVal is = ",dberVal)
let key = Buffer.from('A', 'binary');
let val = Buffer.from('Whatever', 'binary');
let dbi = Buffer.from('beep.', 'binary');
let dbi1 = Buffer.from('seen.', 'binary');
let dbi2 = Buffer.from('boop.', 'binary');

// let dbi = dberVal.env.openDbi({
//   name: dbi3,
//   create: true,
// });


// assert.deepStrictEqual(dberVal.getVal(dbi, key), null);
// console.log("We are here :")
// assert.deepStrictEqual(dberVal.delVal(dbi, key), false);

// assert.deepStrictEqual(dberVal.putVal(dbi, key, val), true);

// assert.deepStrictEqual(dberVal.putVal(dbi, key, val), false);


// assert.deepStrictEqual(dberVal.setVal(dbi, key, val), true);

// assert.deepStrictEqual(dberVal.getVal(dbi, key), val);

// assert.deepStrictEqual(dberVal.delVal(dbi, key), true);
// assert.deepStrictEqual(dberVal.getVal(dbi, key), null);
// console.log("Test cases verified : ")
// test OrdVal OrdItem ordinal numbered event sub db
    
    
  
let preA = Buffer.from('B8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc', 'binary');
let preB = Buffer.from('EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w', 'binary');
let preC = Buffer.from('EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg', 'binary');


let keyA0 = onKey(preA, 0);

let keyB0 = onKey(preB, 0);
let keyB1 = onKey(preB, 1);
let keyB2 = onKey(preB, 2);
let keyB3 = onKey(preB, 3);
let keyB4 = onKey(preB, 4);

let keyC0 = onKey(preC, 0);



// let digA = Buffer.from('ER73b7reENuBahMJsMTLbeyyNPsfTRzKRWtJ3ytmInvw', 'binary');

// let digU = Buffer.from('ER73b7reENuBahMJsMTLbeyyNPsfTRzKRWtJ3ytmInvw', 'binary');
// let digV = Buffer.from('EA4vCeJswIBJlO3RqE-wsE72Vt3wAceJ_LzqKvbDtBSY', 'binary');
// let digW = Buffer.from('EyAyl33W9ja_wLX85UrzRnL4KNzlsIKIA7CrD04nVX1w', 'binary');
// let digX = Buffer.from('EEnwxEm5Bg5s5aTLsgQCNpubIYzwlvMwZIzdOM0Z3u7o', 'binary');
// let digY = Buffer.from('Enrq74_Q11S2vHx1gpK_46Ik5Q7Yy9K1zZ5BavqGDKnk', 'binary');

// let digC = Buffer.from('E-5RimdY_OWoreR-Z-Q5G81-I4tjASJCaP_MqkBbtM2w', 'binary');

// assert.deepStrictEqual(dberVal.getVal(dbi1, keyA0), null);
// assert.deepStrictEqual(dberVal.delVal(dbi1, keyA0) , false);

// assert.deepStrictEqual(dberVal.putVal(dbi1, keyA0, digA), true);

// assert.deepStrictEqual(dberVal.getVal(dbi1, keyA0) , digA);
// assert.deepStrictEqual(dberVal.putVal(dbi1, keyA0, digA), false);
// assert.deepStrictEqual(dberVal.setVal(dbi1, keyA0, digA) , true);
// assert.deepStrictEqual(dberVal.getVal(dbi1, keyA0) , digA);
// assert.deepStrictEqual(dberVal.delVal(dbi1, keyA0) , true);
// assert.deepStrictEqual(dberVal.getVal(dbi1, keyA0) , null);

// console.log("About to open DB#####")

// //test appendOrdValPre
// // empty database
// // assert.deepStrictEqual(dberVal.getVal(dbi1, keyB0) , null);
// let on = dberVal.appendOrdValPre(dbi1, preB, digU);
// console.log("Value of ON = ",on)
// assert.deepStrictEqual(on , 0);
// assert.deepStrictEqual(dberVal.getVal(dbi1, keyB0) , digU);
// assert.deepStrictEqual(dberVal.delVal(dbi1, keyB0) , true);
// assert.deepStrictEqual(dberVal.getVal(dbi1, keyB0) , null);
// // console.log("Value of ON = ",on)

// assert.deepStrictEqual(dberVal.putVal(dbi1, keyA0, val=digA) , true);
// on = dberVal.appendOrdValPre(dbi1, preB, digU)
// assert.deepStrictEqual(on , 0);
// assert.deepStrictEqual(dberVal.getVal(dbi1, keyB0) , digU);
// assert.deepStrictEqual(dberVal.delVal(dbi1, keyB0) , true);
// assert.deepStrictEqual(dberVal.getVal(dbi1, keyB0) , null);




// //     #     # earlier and later pre in db but not same pre


// assert.deepStrictEqual(dberVal.getVal(dbi1, keyA0) , digA);
// assert.deepStrictEqual(dberVal.putVal(dbi1, keyC0, digC) , true);

// on = dberVal.appendOrdValPre(dbi1, preB, digU);
// assert.deepStrictEqual(on , 0);
// assert.deepStrictEqual(dberVal.getVal(dbi1, keyB0) , digU);
// assert.deepStrictEqual(dberVal.delVal(dbi1, keyB0) , true);
// assert.deepStrictEqual(dberVal.getVal(dbi1, keyB0) , null);


// //     later pre only

// assert.deepStrictEqual(dberVal.delVal(dbi1, keyA0) , true);
// assert.deepStrictEqual(dberVal.getVal(dbi1, keyA0) , null);
// assert.deepStrictEqual(dberVal.getVal(dbi1, keyC0) , digC);

// on = dberVal.appendOrdValPre(dbi1, preB, digU);
// assert.deepStrictEqual(on , 0);
// assert.deepStrictEqual(dberVal.getVal(dbi1, keyB0) , digU);

// // // earlier pre and later pre and earlier entry for same pre


// assert.deepStrictEqual(dberVal.putVal(dbi1, keyA0, digA) , true);


// on = dberVal.appendOrdValPre(dbi1, preB, digV);
// assert.deepStrictEqual(on , 1);
// assert.deepStrictEqual(dberVal.getVal(dbi1, keyB1) , digV);


// // // earlier entry for same pre but only same pre
// assert.deepStrictEqual(dberVal.delVal(dbi1, keyA0) , true);
// assert.deepStrictEqual(dberVal.getVal(dbi1, keyA0) , null);
// assert.deepStrictEqual(dberVal.delVal(dbi1, keyC0) , true);
// assert.deepStrictEqual(dberVal.getVal(dbi1, keyC0) , null);

// //      // another value for preB
//      on = dberVal.appendOrdValPre(dbi1, preB, digW);
//      assert.deepStrictEqual(on , 2);
//      assert.deepStrictEqual(dberVal.getVal(dbi1, keyB2) , digW);

// // //yet another value for preB

// on = dberVal.appendOrdValPre(dbi1, preB, digX);
// assert.deepStrictEqual(on , 3);
// assert.deepStrictEqual(dberVal.getVal(dbi1, keyB3) , digX);

// // //       yet another value for preB
// on = dberVal.appendOrdValPre(dbi1, preB, digY);
// assert.deepStrictEqual(on , 4);
// assert.deepStrictEqual(dberVal.getVal(dbi1, keyB4) , digY);
// //# replay preB events in database
// console.log("CALLING getAllOrdItemPreIter=================================>")
// let item = dberVal.getAllOrdItemPreIter(dbi1, preB)


// // Adding all the items to array for comparison
// console.log("arr[0]-===================>", item)
// // console.log("arr[1]-===================>",item.next().value)
// // console.log("arr[2]-===================>",item.next().value)
// // console.log("arr[3]-===================>",item.next().value)
// // console.log("arr[4]-===================>",item.next().value)
// // arr.push(item.next().value)
// // arr.push(item.next().value)
// // arr.push(item.next().value)
// // arr.push(item.next().value)
// // arr.push(item.next().value)


// assert.deepStrictEqual([0,digU] , item[0]);
// assert.deepStrictEqual([1,digV] , item[1]);
// assert.deepStrictEqual([2,digW] , item[2]);
// assert.deepStrictEqual([3,digX] , item[3]);
// assert.deepStrictEqual([4,digY] , item[4]);


// // assert.deepStrictEqual([0,digU] , arr[0]);
// // assert.deepStrictEqual([1,digV] , arr[1]);
// // assert.deepStrictEqual([2,digW] , arr[2]);
// // assert.deepStrictEqual([3,digX] , arr[3]);
// // assert.deepStrictEqual([4,digY] , arr[4]);


// // // #     # resume replay preB events at on = 3

// let item1 = dberVal.getAllOrdItemPreIter(dbi1, preB, 3)
// // arr1.push(item1.next().value)
// // arr1.push(item1 .next().value)

// // console.log("Value of Array is = : ",arr1)
// // console.log("digX  and  digY are : ===================>",digX.toString(), '\n', digY.toString())
// assert.deepStrictEqual([3,digX] , item1[0]);
// assert.deepStrictEqual([4,digY] , item1[1]);
// // #     items = [item for item in dber.getAllOrdItemPreIter(db, preB, on=3)]
// // #     assert items == [(3, digX), (4, digY)]

// // #     # resume replay preB events at on = 5
// let item2 = dberVal.getAllOrdItemPreIter(dbi1, preB, 5)

// assert.deepStrictEqual([] , item2);


// //       replay all events in database with pre events before and after
// assert.deepStrictEqual(dberVal.putVal(dbi1, keyA0, digA), true);
// assert.deepStrictEqual(dberVal.putVal(dbi1, keyC0, digC), true);



// let item3 = dberVal.getAllOrdItemAllPreIter(dbi1)
// console.log("Value of Item 3 = ",item3)
// assert.deepStrictEqual(item3 , [[preA, 0, digA], [preB, 0, digU], [preB, 1, digV],[preB, 2, digW], [preB, 3, digX], [preB, 4, digY],[preC, 0, digC]]);



// // #     # resume replay all starting at preB on=2

// let item4 = dberVal.getAllOrdItemAllPreIter(dbi1, keyB2)
// assert.deepStrictEqual(item4 , [[preB, 2, digW], [preB, 3, digX], [preB, 4, digY],[preC, 0, digC]]);
// console.log("TEST PASSED ==============")


// // #     # resume replay all starting at preC on=1
// let item5 = dberVal.getAllOrdItemAllPreIter(dbi1, onKey(preC, 1));
// assert.deepStrictEqual(item5 , []);



// #     # test Vals dup methods.  dup vals are lexocographic
const vals = [
  Buffer.from('z', 'binary'),
  Buffer.from('m', 'binary'),
  Buffer.from('x', 'binary'),
  Buffer.from('a', 'binary'),
];
//key = Buffer.from('A', 'binary')
//

// let dbi3 = dberVal.env.openDbi({
//   name: dbi2,
//   create: true,
//   dupsort : true,
// });
// // #     key = b'A'
// // #     vals = [b"z", b"m", b"x", b"a"]
// // #     db = dber.env.open_db(key=b'boop.', dupsort=True)



//   assert.deepStrictEqual(dberVal.getVals(dbi3, key), []);
//   assert.deepStrictEqual(dberVal.delVals(dbi3, key), false);
//   console.log("TESTING DONE")
//   assert.deepStrictEqual(dberVal.cntVals(dbi3, key), 0);
  
//   assert.deepStrictEqual(dberVal.putVals(dbi3, key, vals), true);
  
//   assert.deepStrictEqual(dberVal.getVals(dbi3, key), [
//     Buffer.from('a', 'binary'),
//     Buffer.from('m', 'binary'),
//     Buffer.from('x', 'binary'),
//     Buffer.from('z', 'binary'),
//   ]);    // lexocographic order

//   // assert.deepStrictEqual(dberVal.cntVals(dbi3, key), 4);
//   // assert.deepStrictEqual(dberVal.cntVals(dbi3, key), vals.length);   // duplicate
//   assert.deepStrictEqual(dberVal.getVals(dbi3, key), [
//     Buffer.from('a', 'binary'),
//     Buffer.from('m', 'binary'),
//     Buffer.from('x', 'binary'),
//     Buffer.from('z', 'binary'),
//   ]);     // no change
  
//   assert.deepStrictEqual(dberVal.addVal(dbi3, key, Buffer.from('a', 'binary')), false);  // duplicate


//   assert.deepStrictEqual(dberVal.addVal(dbi3, key, Buffer.from('b', 'binary')), true);

//   assert.deepStrictEqual(dberVal.getVals(dbi3, key), [
//     Buffer.from('a', 'binary'),
//     Buffer.from('b', 'binary'),
//     Buffer.from('m', 'binary'),
//     Buffer.from('x', 'binary'),
//     Buffer.from('z', 'binary'),
//   ]);   



//  item = dberVal.getValsIter(dbi3, key)

//   assert.deepStrictEqual(item, [
//     Buffer.from('a', 'binary'),
//     Buffer.from('b', 'binary'),
//     Buffer.from('m', 'binary'),
//     Buffer.from('x', 'binary'),
//     Buffer.from('z', 'binary'),
//   ]);
  
//   assert.deepStrictEqual(dberVal.delVals(dbi3, key), true);
//   assert.deepStrictEqual(dberVal.getVals(dbi3, key), []);   
   
//   assert.deepStrictEqual(dberVal.putVals(dbi3, key,vals), true); 
  
//   assert.deepStrictEqual(dberVal.delVals(dbi3, key), true);
//   assert.deepStrictEqual(dberVal.getVals(dbi3, key), []);  
//   assert.deepStrictEqual(dberVal.putVals(dbi3, key,vals), true);  
//   console.log("TESTING DONE ******************************") 
// // // 


// #     # test IoVals insertion order dup methods.  dup vals are insertion order
// #     key = b'A'
// #     vals = [b"z", b"m", b"x", b"a"]
// #     db = dber.env.open_db(key=b'peep.', dupsort=True)
let dbi4 = dberVal.env.openDbi({
  name: Buffer.from('peep.', 'binary'),
  create: true,
  dupsort : true,
});

assert.deepStrictEqual(dberVal.getIoVals(dbi4, key), []);
assert.deepStrictEqual(dberVal.getIOValsLast(dbi4, key), null);
assert.deepStrictEqual(dberVal.cntIoVals(dbi4, key), 0);

assert.deepStrictEqual(dberVal.delIoVals(dbi4, key), false);
assert.deepStrictEqual(dberVal.putIOVals(dbi4, key, vals), true);

assert.deepStrictEqual(dberVal.getIoVals(dbi4, key), vals);  //  # preserved insertion order
assert.deepStrictEqual(dberVal.cntIoVals(dbi4, key), 4)
assert.deepStrictEqual(dberVal.getIOValsLast(dbi4, key), vals[vals.length - 1]);
assert.deepStrictEqual(dberVal.putIOVals(dbi4, key, [Buffer.from('a', 'binary')]), false); // duplicate
// console.log("We are Here ")
assert.deepStrictEqual(dberVal.getIoVals(dbi4, key), vals);  //  no change

assert.deepStrictEqual(dberVal.addIoVal(dbi4, key, [Buffer.from('b', 'binary')]), true); 
assert.deepStrictEqual(dberVal.addIoVal(dbi4, key, [Buffer.from('a', 'binary')]), false); 
// assert.deepStrictEqual(dberVal.getIoVals(dbi4, key), [
//       Buffer.from('z', 'binary'),
//       Buffer.from('m', 'binary'),
//       Buffer.from('x', 'binary'),
//       Buffer.from('a', 'binary'),
//       Buffer.from('b', 'binary'),
//     ]);

    // assert.deepStrictEqual(dberVal.getValsIter(dbi4, key), [
    //   Buffer.from('z', 'binary'),
    //   Buffer.from('m', 'binary'),
    //   Buffer.from('x', 'binary'),
    //   Buffer.from('a', 'binary'),
    //   Buffer.from('b', 'binary'),
    // ]);

    assert.deepStrictEqual(dberVal.delIoVals(dbi4, key), true);

    // assert.deepStrictEqual(dberVal.getIoVals(dbi4, key), []);
    assert.deepStrictEqual(dberVal.putIOVals(dbi4, key, vals), true);
    console.log("######################### CALLING getIoVals ############################################")
     for (let val in vals){assert.deepStrictEqual(dberVal.delIoVal(dbi4, key, vals[val]), true);}
     assert.deepStrictEqual(dberVal.getIoVals(dbi4, key), []);
// #     assert dber.getIoVals(db, key) == []
// #     assert dber.putIoVals(db, key, vals) == True
// #     for val in sorted(vals):
// #         assert dber.delIoVal(db, key, val)
// #     assert dber.getIoVals(db, key) == []
// #     #delete and add in odd order
// #     assert dber.putIoVals(db, key, vals) == True
// #     assert dber.delIoVal(db, key, vals[2])
// #     assert dber.addIoVal(db, key, b'w')
// #     assert dber.delIoVal(db, key, vals[0])
// #     assert dber.addIoVal(db, key, b'e')
// #     assert dber.getIoVals(db, key) == [b'm', b'a', b'w', b'e']

// #     # Test getIoValsAllPreIter(self, db, pre)
// #     vals0 = [b"gamma", b"beta"]
// #     sn = 0
// #     key = snKey(pre, sn)
// #     assert dber.addIoVal(db, key, vals0[0]) == True
// #     assert dber.addIoVal(db, key, vals0[1]) == True

// #     vals1 = [b"mary", b"peter", b"john", b"paul"]
// #     sn += 1
// #     key = snKey(pre, sn)
// #     assert dber.putIoVals(db, key, vals1) == True

// #     vals2 = [b"dog", b"cat", b"bird"]
// #     sn += 1
// #     key = snKey(pre, sn)
// #     assert dber.putIoVals(db, key, vals2) == True

// #     vals = [bytes(val) for val in dber.getIoValsAllPreIter(db, pre)]
// #     allvals = vals0 + vals1 + vals2
// #     assert vals == allvals

// #     # Test getIoValsLastAllPreIter(self, db, pre)
// #     pre = b'B4ejWzwQPYGGwTmuupUhPx5_yZ-Wk1xEHHzq7K0gzhcc'
// #     vals0 = [b"gamma", b"beta"]
// #     sn = 0
// #     key = snKey(pre, sn)
// #     assert dber.addIoVal(db, key, vals0[0]) == True
// #     assert dber.addIoVal(db, key, vals0[1]) == True

// #     vals1 = [b"mary", b"peter", b"john", b"paul"]
// #     sn += 1
// #     key = snKey(pre, sn)
// #     assert dber.putIoVals(db, key, vals1) == True

// #     vals2 = [b"dog", b"cat", b"bird"]
// #     sn += 1
// #     key = snKey(pre, sn)
// #     assert dber.putIoVals(db, key, vals2) == True

// #     vals = [bytes(val) for val in dber.getIoValLastAllPreIter(db, pre)]
// #     lastvals = [vals0[-1], vals1[-1], vals2[-1]]
// #     assert vals == lastvals

// #     # Test getIoValsAnyPreIter(self, db, pre)
// #     pre = b'BQPYGGwTmuupUhPx5_yZ-Wk1x4ejWzwEHHzq7K0gzhcc'
// #     vals0 = [b"gamma", b"beta"]
// #     sn = 1  # not start at zero
// #     key = snKey(pre, sn)
// #     assert dber.addIoVal(db, key, vals0[0]) == True
// #     assert dber.addIoVal(db, key, vals0[1]) == True

// #     vals1 = [b"mary", b"peter", b"john", b"paul"]
// #     sn += 1
// #     key = snKey(pre, sn)
// #     assert dber.putIoVals(db, key, vals1) == True

// #     vals2 = [b"dog", b"cat", b"bird"]
// #     sn += 2  # gap
// #     key = snKey(pre, sn)
// #     assert dber.putIoVals(db, key, vals2) == True

// #     vals = [bytes(val) for val in dber.getIoValsAnyPreIter(db, pre)]
// #     allvals = vals0 + vals1 + vals2
// #     assert vals == allvals

// #     # Setup Tests for getIoItemsNext and getIoItemsNextIter
// #     edb = dber.env.open_db(key=b'escrow.', dupsort=True)
// #     aKey = snKey(pre=b'A', sn=1)
// #     aVals = [b"z", b"m", b"x"]
// #     bKey = snKey(pre=b'A', sn=2)
// #     bVals = [b"o", b"r", b"z"]
// #     cKey = snKey(pre=b'A', sn=4)
// #     cVals = [b"h", b"n"]
// #     dKey = snKey(pre=b'A', sn=7)
// #     dVals = [b"k", b"b"]

// #     assert dber.putIoVals(edb, key=aKey, vals=aVals)
// #     assert dber.putIoVals(edb, key=bKey, vals=bVals)
// #     assert dber.putIoVals(edb, key=cKey, vals=cVals)
// #     assert dber.putIoVals(edb, key=dKey, vals=dVals)

// #     # Test getIoItemsNext(self, db, key=b"")
// #     # aVals
// #     items = dber.getIoItemsNext(edb)  #  get first key in database
// #     assert items  # not empty
// #     ikey = items[0][0]
// #     assert  ikey == aKey
// #     vals = [val for  key, val in items]
// #     assert vals == aVals

// #     items = dber.getIoItemsNext(edb, key=aKey, skip=False)  # get aKey in database
// #     assert items  # not empty
// #     ikey = items[0][0]
// #     assert  ikey == aKey
// #     vals = [val for  key, val in items]
// #     assert vals == aVals

// #     items = dber.getIoItemsNext(edb, key=aKey)  # get bKey in database
// #     assert items  # not empty
// #     ikey = items[0][0]
// #     assert  ikey == bKey
// #     vals = [val for  key, val in items]
// #     assert vals == bVals

// #     items = dber.getIoItemsNext(edb, key=b'', skip=False)  # get first key in database
// #     assert items  # not empty
// #     ikey = items[0][0]
// #     assert  ikey == aKey
// #     vals = [val for  key, val in items]
// #     assert vals == aVals

// #     # bVals
// #     items = dber.getIoItemsNext(edb, key=ikey)
// #     assert items  # not empty
// #     ikey = items[0][0]
// #     assert  ikey == bKey
// #     vals = [val for key, val in items]
// #     assert vals == bVals

// #     # cVals
// #     items = dber.getIoItemsNext(edb, key=ikey)
// #     assert items  # not empty
// #     ikey = items[0][0]
// #     assert  ikey == cKey
// #     vals = [val for key, val in items]
// #     assert vals == cVals

// #     # dVals
// #     items = dber.getIoItemsNext(edb, key=ikey)
// #     assert items  # not empty
// #     ikey = items[0][0]
// #     assert  ikey == dKey
// #     vals = [val for key, val in items]
// #     assert vals == dVals

// #     # none
// #     items = dber.getIoItemsNext(edb, key=ikey)
// #     assert items == []  # empty
// #     assert not items

// #     # Test getIoItemsNextIter(self, db, key=b"")
// #     #  get dups at first key in database
// #     # aVals
// #     items = [item for item in dber.getIoItemsNextIter(edb)]
// #     assert items  # not empty
// #     ikey = items[0][0]
// #     assert  ikey == aKey
// #     vals = [val for  key, val in items]
// #     assert vals == aVals

// #     items = [item for item in dber.getIoItemsNextIter(edb, key=aKey, skip=False)]
// #     assert items  # not empty
// #     ikey = items[0][0]
// #     assert  ikey == aKey
// #     vals = [val for  key, val in items]
// #     assert vals == aVals

// #     items = [item for item in dber.getIoItemsNextIter(edb, key=aKey)]
// #     assert items  # not empty
// #     ikey = items[0][0]
// #     assert  ikey == bKey
// #     vals = [val for  key, val in items]
// #     assert vals == bVals

// #     items = [item for item in dber.getIoItemsNextIter(edb, key=b'', skip=False)]
// #     assert items  # not empty
// #     ikey = items[0][0]
// #     assert  ikey == aKey
// #     vals = [val for  key, val in items]
// #     assert vals == aVals
// #     for key, val in items:
// #         assert dber.delIoVal(edb, ikey, val) == True

// #     # bVals
// #     items = [item for item in dber.getIoItemsNextIter(edb, key=ikey)]
// #     assert items  # not empty
// #     ikey = items[0][0]
// #     assert  ikey == bKey
// #     vals = [val for key, val in items]
// #     assert vals == bVals
// #     for key, val in items:
// #         assert dber.delIoVal(edb, ikey, val) == True

// #     # cVals
// #     items = [item for item in dber.getIoItemsNextIter(edb, key=ikey)]
// #     assert items  # not empty
// #     ikey = items[0][0]
// #     assert  ikey == cKey
// #     vals = [val for key, val in items]
// #     assert vals == cVals
// #     for key, val in items:
// #         assert dber.delIoVal(edb, ikey, val) == True

// #     # dVals
// #     items = [item for item in dber.getIoItemsNext(edb, key=ikey)]
// #     assert items  # not empty
// #     ikey = items[0][0]
// #     assert  ikey == dKey
// #     vals = [val for key, val in items]
// #     assert vals == dVals
// #     for key, val in items:
// #         assert dber.delIoVal(edb, ikey, val) == True

// #     # none
// #     items = [item for item in dber.getIoItemsNext(edb, key=ikey)]
// #     assert items == []  # empty
// #     assert not items


 }



 function test_fetchkeldel(){
    // """
    // Test fetching full KEL and full DEL from Baser
    // """
    // Test using context manager
    let preb = Buffer.from('BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc', 'utf-8');
    
    let digb = Buffer.from('EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4', 'utf-8')
   let sn = 3
   let vs = versify(null, Serials.json, 20);
   assert.deepStrictEqual(vs , 'KERI10JSON000014_')
    // assert vs == 'KERI10JSON000014_'
    let ked = {vs: vs, pre: preb.toString(), sn : sn.toString(16),ilk: "rot", dig:digb.toString() }
    let skedb = Buffer.from(JSON.stringify(ked), 'binary') 
//console.log("Value of KED = ",ked)
    // let json = {"vs":"KERI10JSON000014_","pre":"BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhc'
    // 'c","sn":"3","ilk":"rot","dig":"EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4"'
    // }
// assert.deepStrictEqual(skedb , Buffer.from(ked))
    




sig0b = Buffer.from('AAz1KAV2z5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5AzJ91Timrykocna6Z_pQBl2gt59I_F6BsSwFbIOG1TDQ', 'binary')
sig1b = Buffer.from('AB_pQBl2gt59I_F6BsSwFbIOG1TDQz1KAV2z5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5AzJ91Timrykocna6Z', 'binary')

wit0b = Buffer.from('BmuupUhPx5_yZ-Wk1x4ejhccWzwEHHzq7K0gzQPYGGwT', 'binary')
wit1b = Buffer.from('BjhccWzwEHHzq7K0gzmuupUhPx5_yZ-Wk1x4eQPYGGwT', 'binary')
wsig0b = Buffer.from('0A1Timrykocna6Z_pQBl2gt59I_F6BsSwFbIOG1TDQz1KAV2z5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5AzJ9', 'binary')
wsig1b = Buffer.from('0A5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5Az_pQBl2gt59I_F6BsSwFbIOG1TDQz1KAV2zJ91Timrykocna6Z', 'binary')


// //    test getKelIter
const dberGen = openLogger('test', null);
const db = dberGen.next().value;

        sn = 0
        let    key = snKey(preb, sn)
        assert.deepStrictEqual(key, Buffer.from('BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc.00000000000000000000000000000000', 'binary'))
        
        let vals0 = [skedb];
    
        assert.deepStrictEqual( db.addKe(key, vals0[0]), true)
  let vals1 = [Buffer.from('mary', 'binary'),
  Buffer.from('peter', 'binary'),
  Buffer.from('john', 'binary'),
  Buffer.from('paul', 'binary')]

  sn += 1
  key = snKey(preb, sn)
  for (let val in vals1){assert.deepStrictEqual( db.addKe(key, vals1[val]), true)}


  let vals2 = [Buffer.from('dog', 'binary'),
  Buffer.from('cat', 'binary'),
  Buffer.from('bird', 'binary')]
  sn += 1
  key = snKey(preb, sn)
  for (let val in vals2){assert.deepStrictEqual( db.addKe(key, vals2[val]), true)}



// // ================== PENDING 
  // let vals = db.getKelIter(preb)
  // console.log("VALUE FROM GETKELITER = ",vals.toString())
//    let data = vals


   
//    console.log("VALUE OF DATA IS = ",vals0,'\n', vals1 , '\n', vals2) //  
//   let val01 =  vals0.concat(vals1 , vals2)
  
// console.log("  #########################################################  ",  val01.toString() , '\n', data.toString())
// assert.deepStrictEqual(data , val01)
//  let response = Buffer.compare(data,val01 )  // Buffer.concat([val01 , val02 , val03])
//         vals = [bytes(val) for val in db.getKelIter(preb)]
//         allvals = vals0 + vals1 + vals2
//         assert vals == allvals

// ========================================
 //     # test getKelEstIter
    // preb = Buffer.from('B4ejhccWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x', 'binary')
    // sn = 0
    // key = snKey(preb, sn)
    // assert.deepStrictEqual(key , Buffer.from('B4ejhccWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x.00000000000000000000000000000000', 'binary'))

   

    //     vals0 = [skedb]
    //     console.log("VALUE OF KEY1 = ",key.toString())
    //     assert.deepStrictEqual( db.addKe(key, vals0[0]), true)
        


    //    // vals1 = [b"mary", b"peter", b"john", b"paul"]
    //     sn += 1
    //     key = snKey(preb, sn)
    //     for (let val in vals1){assert.deepStrictEqual( db.addKe(key, vals1[val]), true)}


    // //     vals2 = [b"dog", b"cat", b"bird"]
    //     sn += 1
    //     key = snKey(preb, sn)
    //     for (let val in vals2){assert.deepStrictEqual( db.addKe(key, vals2[val]), true)}
    //     console.log("TEST DONE ####################### ")

        // =========================== PENDING 
        // let data1 = db.getKelIter(preb)

        //   = []
        //  data1.push(vals.next().value)
        //  data1.push(vals.next().value)
        //  data1.push(vals.next().value)
     
        
        // console.log("VALUE OF vals0 IS = ",vals0[vals0.length-1].toString() ,'\n', vals1[vals1.length-1].toString() ,'\n', vals2[vals2.length-1].toString()) //  
        // console.log("VALUE OF DATA = ", data1.toString())
        // val01 =  vals0.concat(vals0, vals1 , vals2)
   //  assert.deepStrictEqual(data1 , val01)
    //     vals = [bytes(val) for val in db.getKelEstIter(preb)]
    //     lastvals = [vals0[-1], vals1[-1], vals2[-1]]
    //     assert vals == lastvals

// =========================
    //     # test getDelIter
    // preb = Buffer.from('BTmuupUhPx5_yZ-Wk1x4ejhccWzwEHHzq7K0gzQPYGGw', 'binary')
  
    //     sn = 1  // do not start at zero
    //     key = snKey(preb, sn)
  
    //     assert.deepStrictEqual(key , Buffer.from('BTmuupUhPx5_yZ-Wk1x4ejhccWzwEHHzq7K0gzQPYGGw.00000000000000000000000000000001', 'binary'))
  
    //     vals0 = [skedb]
    //     assert.deepStrictEqual( db.addKe(key, vals0[0]), true)
  

    //     vals1 = [b"mary", b"peter", b"john", b"paul"]
        // sn += 1
        // key = snKey(preb, sn)
        // for (let val in vals1){assert.deepStrictEqual( db.addKe(key, vals1[val]), true)}
  

  
        // sn += 3  // skip make gap in SN
        // for (let val in vals2){assert.deepStrictEqual( db.addKe(key, vals2[val]), true)}


  // =================== PENDING
    //     vals = [bytes(val) for val in db.getDelIter(preb)]
    //     allvals = vals0 + vals1 + vals2
    //     assert vals == allvals
// ================================
    // assert not os.path.exists(db.path)
    // """ End Test """
 }

 test_fetchkeldel();