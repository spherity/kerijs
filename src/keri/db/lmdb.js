const path = require('path');
const fs = require('fs-extra')
var os = require('os');
const lmdb = require('node-lmdb');
const { snKey, splitKeyON, onKey } = require('./database');
const { CryOneSizes } = require('../core/derivationCode&Length');
const { map } = require('collections/shim-object');
const ProemSize = 33
const MaxProem = parseInt("f" * (ProemSize - 1), 16);
const MaxHexDigits = 6;
const MaxForks = parseInt('f'.repeat(MaxHexDigits), 16); // # 16777215
const MaxON = parseInt("f" * 32, 16)  // largest possible ordinal number, sequence or first seen
const { pad } = require('./util');

/**
 *     LBDBer base class for LMDB manager instances.
    Creates a specific instance of an LMDB database directory and environment.

    Attributes:
        .name is LMDB database name did2offer
        .temp is Boolean, True means open db in /tmp directory
        .headDirPath is head directory path for db
        .mode is numeric os dir permissions for db directory
        .path is LMDB main (super) database directory path
        .env is LMDB main (super) database environment
        .opened is Boolean, True means LMDB .env at .path is opened.
                            Otherwise LMDB .env is closed

 */

class LMDBer {

  /**
   *     Setup main database directory at .dirpath.
          Create main database environment at .env using .dirpath.
  
          Parameters:
              name is str directory path name differentiator for main database
                  When system employs more than one keri database, name allows
                  differentiating each instance by name
              temp is boolean, assign to .temp
                  True then open in temporary directory, clear on close
                  Othewise then open persistent directory, do not clear on close
              headDirPath is optional str head directory pathname for main database
                  If not provided use default .HeadDirpath
              dirMode is int numeric os dir permissions for database directory
                  default is use os defaults and not set the dirMode
              reopen is boolean, IF True then database will be reopened by this init
   */


  constructor(headDirPath = null, name = 'main', temp = true) {

    var keriDbDirPath;      //database directory location has not been set up yet
    var keriDB;            //database environment has not been set up yet
    const MAX_DB_COUNT = 16;
    const DATABASE_DIR_PATH = "/var/keri/db"
    const ALT_DATABASE_DIR_PATH = path.join("~", '.keri/db')
    const DB_KEY_EVENT_LOG_NAME = Buffer.from('kel', 'binary')

    //const HeadDirPath = "/usr/local/var"  // default in /usr/local/var
    //const TailDirPath = "keri/db"
    //const AltHeadDirPath = "~"  //  put in ~ as fallback when desired not permitted
    const AltTailDirPath = ".keri/db"
    const TempHeadDir = "/tmp"
    const TempPrefix = "keri_lmdb_"
    const TempSuffix = "_test"

    let HeadDirPath = '/var';
    let localHeadDirPath = headDirPath;
    const TailDirPath = 'keri/db';
    const AltHeadDirPath = path.join('~', '.keri/db');
    // const AltTailDirPath = '.keri/db';
    // let ALT_DATABASE_DIR_PATH =
    const MaxNamedDBs = 16;
    try {
      if (temp) {
        var tmpDir = os.tmpdir();
        var suffix = '/keri_lmdb_test';
        if (!fs.pathExistsSync(`${tmpDir}${suffix}`)) {
          console.log("Path doesn't exist")
          HeadDirPath = fs.mkdirSync(`${tmpDir}${suffix}`, 0o777);

        }
        console.log("this.path ===============+=========>", tmpDir)
        this.path = path.join(`${tmpDir}${suffix}`, name);
        console.log("this.path ===============+>", this.path)
        // fs.mkdtempSync(`${tmpDir}${suffix}`)
        fs.mkdirSync(this.path, 0o777);


      }
    } catch (e) {
      console.log('Error while creating directory', e);
    }
    if (!localHeadDirPath) { localHeadDirPath = `${HeadDirPath}/${TailDirPath}`; }
    let baseDirPath = path.resolve(resolveHome(localHeadDirPath));
    if (!fs.pathExistsSync(baseDirPath)) {
      console.log("baseDirPath  PPathexist ============>", baseDirPath)
      // console.log("Inside fs.pathExistsSync(baseDirPath)", fs.mkdirsSync(baseDirPath, 0o777))
      try {
        fs.mkdirsSync(baseDirPath, 0o777);
      } catch (e) {
        console.log("Inside Catch", baseDirPath)
        baseDirPath = AltHeadDirPath;
        baseDirPath = path.resolve(resolveHome(baseDirPath));
        console.log("Inside Catch baseDirPath", baseDirPath)
        if (!fs.pathExistsSync(baseDirPath)) {
          fs.mkdirsSync(baseDirPath, 0o777);
        }
      }
    } else if (fs.accessSync(baseDirPath, fs.constants.F_OK || fs.constants.W_OK
      || fs.constants.R_OK)) {
      console.log("Inside fs.accessSync")
      baseDirPath = AltHeadDirPath;
      baseDirPath = path.resolve(resolveHome(baseDirPath));
      if (!fs.pathExistsSync(baseDirPath)) { fs.mkdirsSync(baseDirPath, 0o777); }
    }
    const env = new lmdb.Env();
    console.log("baseDirPath =################################>", fs.mkdtempSync(`${tmpDir}${suffix}`))
    env.open({ path: fs.mkdtempSync(`${tmpDir}${suffix}`), mapSize: 2 * 1024 * 1024 * 1024, maxDbs: MaxNamedDBs });
    console.log("env ==============>", env)
    this.path = baseDirPath;
    this.env = env;

    this.headDirPath = headDirPath;
    this.name = name;
    this.temp = temp;
    // file = _os.path.join(dir, prefix + name + suffix)
    if (this.temp) {
      console.log("INside This.temp")
      tmpDir = os.tmpdir();
      suffix = '/keri_lmdb_test';
      HeadDirPath = fs.mkdtempSync(`${tmpDir}${suffix}`);
      console.log("this.headDirPath -=====================>", fs.mkdtempSync(`${tmpDir}${suffix}`))
      this.path = path.join(HeadDirPath, this.name);
      fs.mkdirSync(this.path);
    } else if (!this.headDirPath) {
      this.headDirPath = HeadDirPath;
      console.log("this.headDirPath -=====================@###############>", this.headDirPath)
      this.path = path.join(this.headDirPath, TailDirPath, this.name);

      if (!fs.pathExistsSync(this.path)) {
        try {
          fs.mkdirSync(this.path, { recursive: true });
        } catch (error) {
          this.path = path.join(process.env.HOME, this.headDirPath, TailDirPath, this.name);
        }
      } else {
        console.log('Directory already exist');
      }
    }
  }
  // constructor(name='main', temp=false, headDirPath=null, dirMode=null, reopen=true){

  //     this.name = name
  //     if(temp)
  //         this.temp = true
  //     else
  //     this.temp = false

  //     this.headDirPath = headDirPath
  //     this.dirMode = dirMode
  //     this.path = null
  //     this.env = null
  //     this.opened = false

  //     if(reopen)
  //     this.reopen(headDirPath=this.headDirPath, dirMode=this.dirMode)

  // }


  /**
   * @description  Use or Create if not preexistent, directory path for lmdb at .path
      Open lmdb and assign to .env

   * @param {*} temp  temp is optional boolean:
                      If None ignore Otherwise
                      Assign to .temp
                      If True then open temporary directory, clear on close
                      If False then open persistent directory, do not clear on close
   * @param {*} headDirPath headDirPath is optional str head directory pathname of main database
                            If not provided use default .HeadDirpath
   * @param {*} dirMode 
   */
  reopen(temp = null, headDirPath = null, dirMode = null) {

    if (temp != null) {
      if (temp)
        this.temp = true
      else
        this.temp = false   // need .temp for clear on .close
    }

    if (headDirPath)
      headDirPath = this.headDirPath

    if (dirMode)
      dirMode = this.dirMode

    if (this.temp) {
      headDirPath = fs.mkdirSync(`${tmpDir}${suffix}`)
    }
  }

  /**
   * @description : Write serialized bytes val to location key in db
     Does not overwrite.
     Returns True If val successfully written Else False
     Returns False if val at key already exitss
   * @param {*} db  db is opened named sub db with dupsort=False
   * @param {*} key key is bytes of key within sub db's keyspace
   * @param {*} value val is bytes of value to be written
   * @returns 
   */



  /**
* @description Write each entry from list of bytes vals to key in db.
* Adds to existing values at key if any
*/
  putVal(db, key, value) {
    var txn = null
    var dbi = null
    try {
      console.log("About to open db")
      dbi = this.env.openDbi({
        name: db,
        create: true, // will create if database did not exist
      });
      console.log(" db Opened")
      // const dbi = this.env.openDbi({
      //   name: db,
      //   create: true, // will create if database did not exist,
      // });

      txn = this.env.beginTxn();
      // console.log("Key and value are :",key.toString() ,'\n', value.toString())
      txn.putBinary(dbi, key, value, { keyIsBuffer: true, noOverwrite: true });
      txn.commit();
      dbi.close();

      return true;
    } catch (error) {

      console.log('\nERROR:', error);
      txn.commit();
      dbi.close();
      return false;
    }
  }

  //  putVal(db, key, value) {
  //     try {
  //       const dbi = this.env.openDbi({
  //         name: db,
  //         create: true, // will create if database did not exist,
  //       });

  //       const txn = this.env.beginTxn();
  //       txn.putBinary(dbi, key, value, { keyIsBuffer: true, overwrite: false });
  //       txn.commit();
  //       dbi.close();
  //       return true;
  //     } catch (error) {
  //       console.log('\nERROR:', error);
  //       return false;
  //     }
  //   }

  /**
* @description  Write serialized bytes val to location key in db
      Overwrites existing val if any
      Returns True If val successfully written Else False
* @param {} dbi db is opened named sub db with dupsort=False
* @param {*} key key is bytes of key within sub db's keyspace
* @param {*} value val is bytes of value to be written
*/
  setVal(db, key, value) {
    try {

      const dbi = this.env.openDbi({
        name: db,
        // create: true, // will create if database did not exist
      });
      console.log("DB opened Setval")
      // key = encoder.encode(key)
      const txn = this.env.beginTxn();
      txn.putBinary(dbi, key, value, { keyIsBuffer: true });
      txn.commit();
      dbi.close();
      //  this.env.close();
      return true;
    } catch (error) {
      console.log('ERROR =======================>: \n', error);
      return false;
    }
  }



  /**
   * @description Return val at key in db
        Returns None if no entry at key
   * @param {*} db db is opened named sub db with dupsort=False
   * @param {*} key key is bytes of key within sub db's keyspace
   * @returns 
   */
  getVal(db, key) {

    try {
      var dbi = this.env.openDbi({
        name: db,
      });
      var txn = this.env.beginTxn();
      // txn = this.env.beginTxn();
      const data = txn.getBinary(dbi, key);
      dbi.close();
      txn.commit();
      return data;
    } catch (error) {
      console.log('ERROR Name is :\n', error);
      return null;
    }
  }


  /**
   * @description Deletes value at key in db.
        Returns True If key exists in database Else False

   * @param {*} db db is opened named sub db with dupsort=False
   * @param {*} key key is bytes of key within sub db's keyspace
   * @returns 
   */

  delVal(db, key) {

    try {
      const dbi = this.env.openDbi({
        name: db,
        // will create if database did not exist
      });
      const txn = this.env.beginTxn();

      txn.del(dbi, key);
      txn.commit();
      dbi.close();
      return true;
    } catch (error) {
      console.log('ERROR :\n', error);

      return false;
    }
  }



  getValsIter(db, key) {

    let arr = [];
    try {
      const dbi = this.env.openDbi({
        name: db,
        //  create: true, // will create if database did not exist
        dupSort: true,
      });
      let response = null;
      const txn = this.env.beginTxn();
      const cursor = new lmdb.Cursor(txn, dbi, { keyIsBuffer: true });
      // let vals = cursor.goToRange(key)
      console.log("vals ============>", key)
      if (cursor.goToRange(key) != null) {
        // for (val in cursor.goToNextDup() )
        // yield val
        do {
          cursor.getCurrentBinary((keyParam, data) => {

            response = data.slice(33 , data.length);;
          });
          arr.push(response);
        } while (cursor.goToNextDup());
      }

      txn.commit();
      dbi.close();
      return arr;
    } catch (error) {
      console.log("getValsIter  ERROR IS =====================+", error)
      return false;
    }
  }

  /**
   * @description   Appends val in order after last previous key with same pre in db.
                    Returns ordinal number, on, of appended entry. Appended on is 1 greater
                    than previous latest on.
                    Uses snKey(pre, on) for entries.
  
          Append val to end of db entries with same pre but with on incremented by
          1 relative to last preexisting entry at pre.
   * @param {*} db    db is opened named sub db with dupsort=False
   * @param {*} pre   pre is bytes identifier prefix for event
   * @param {*} val   val is event digest
   */


  appendOrdValPre(db, pre, val) {
    //  set key with fn at max and then walk backwards to find last entry at pre
    //  if any otherwise zeroth entry at pre

    let key = snKey(pre, MaxON)

    const dbi = this.env.openDbi({
      name: db,
      //  create: true, // will create if database did not exist
    });
    let on = 0;
    const txn = this.env.beginTxn();
    let ckey = null
    const cursor = new lmdb.Cursor(txn, dbi, { keyIsBuffer: true });
    if (!cursor.goToRange(key)) {
      console.log("Set Range not Present =======================>")
      // console.log(" set Range not present =================",(cursor.goToLast()).toString())
      if (cursor.goToLast() != null) {
        //  ckey = cursor.goToLast();
        // console.log("ckey Last Key ======================>",ckey.toString())
        cursor.getCurrentBinary((keyParam, data) => {
          console.log("Cursor Last Key #############=>", keyParam.toString(), data)
          ckey = keyParam.toString()
        })

        let keys = splitKeyON(ckey)
        console.log("cpre cn for last key are :  ========== ", keys[0], keys[1])
        if (keys[0] == pre) {
          on = keys[1] + 1
          //
        }
      }

    }
    else {
      console.log("Set Range Present ==================>")
      let ckey = cursor.goToFirst()

      console.log("Value of first key ===========>", ckey.toString())
      cursor.getCurrentBinary((keyParam, data) => {
        console.log("data = = = = = == ======>", keyParam.toString(), `\n`, data.toString());
        ckey = keyParam
      })
      console.log("Value of Current ckey  ===========>", ckey.toString())
      //cpre, cn = splitKeyON(ckey)
      let keys = splitKeyON(ckey)
      console.log("Keys are ===============>", keys)
      if (keys[0] == pre) {
        throw new Error(`Number part of key ${ckey}  exceeds maximum size.`)
      } else {
        for (var found = cursor.goToFirst(); found !== null; found = cursor.goToNext()) {
          console.log("-----> key:", found.toString());
        }
        if (cursor.goToPrev() != null) {
          // console.log("Inside cursor previous part",cursor.goToPrev())
          //  let ckey = cursor.goToPrev()
          //  console.log("Cursor Go to next key is =============>",ckey.toString())
          //  ckey = cursor.goToPrev()
          //  console.log("ckey Previous = ",ckey.toString())
          cursor.getCurrentBinary((keyParam, data) => {
            // let   result = keyParam.slice(7, data.length);
            console.log("goToPrev data,keyParam ###########################>             ", keyParam.toString(), '\n', data.toString());
            ckey = keyParam
          })

          let keys = splitKeyON(ckey);
          console.log("cpre cn for Previous key are :  =========== \n", keys[0].toString(), '\n PRE:', pre.toString())
          if (keys[0] == pre) {
            on = keys[1] + 1

          }
        }
      }


    }
    key = onKey(pre, on)
    console.log("Keys and Value are  : ===============>", key.toString(), val.toString())
    try {

      txn.putBinary(dbi, key, val, { keyIsBuffer: true, overwrite: false })

    } catch (e) {
      console.log("Inside Catch ")
      txn.commit();
      dbi.close();
      throw new Error(`Failed appending ${val} at ${key}.`)
    }
    // if(!txn.putBinary(dbi, key, val, { keyIsBuffer: true, overwrite: false })){
    //     throw new Error(`Failed appending ${val} at ${key}.`) 
    // }
    txn.commit();
    dbi.close();
    console.log("TX and DB Closed ", on)
    console.log("Value of ON = ", on)
    return on
  }


  /**
    * @description  Returns iterator of duple item, (on, dig), at each key over all ordinal
        numbered keys with same prefix, pre, in db. Values are sorted by
        snKey(pre, on) where on is ordinal number int.
        Returned items are duples of (on, dig) where on is ordinal number int
        and dig is event digest for lookup in .evts sub db.

        Raises StopIteration Error when empty.
    * @param {*} db db is opened named sub db with dupsort=False
    * @param {*} pre pre is bytes of itdentifier prefix
    * @param {*} on on is int ordinal number to resume replay
    */
  getAllOrdItemPreIter(db, pre, on = 0) {

    console.log("Trying to Open DB===========================")
    const dbi = this.env.openDbi({
      name: db,
    });
    var arr = []
    console.log("Value of ON = ", on)
    let key = onKey(pre, on);
    // console.log("Keys are :  ========== ",key.toString())
    const txn = this.env.beginTxn();
    try {
      const cursor = new lmdb.Cursor(txn, dbi, { keyIsBuffer: true });
      const cnt = 0;
      //  let arr = []
      var val;
      let result = false;
      if (cursor.goToRange(key) == null) {
        console.log("INside coursor go to Range :")
        // do {
        //   cursor.getCurrentNumber((keyParam, data) => {
        //     result = data.slice(7, data.length);
        //   });

        //   yield result;
        //   key = snKey(pre, cnt + 1);
        // } while (cursor.goToNextDup());
        // txn.commit();
        // dbi.close();
        return []
      }
      do {
        cursor.getCurrentBinary((keyParam, data) => {
          result = keyParam;
          val = data;
        });


        key = splitKeyON(result);
        console.log("Inside DO ---------------->", key[1], val.toString())
        // console.log("CN and VAL are : ",key[1], val)
        if (key[0] != pre) {

          console.log("Inside Break")
          break
        }
        console.log("WE ARE HERE ")
        arr.push([key[1], val])
        // yield [key[1], val]
        console.log(" yield Done ====================>")
        // arr.push({cn : key[1] , val : val})
        // {cn : key[1] , val : val};
      } while (cursor.goToNext() != null);
      return arr
    } catch (error) {
      console.log("ERROR ", error)
      return false;
    } finally {
      console.log("INSIDE FINALLY ====================")
      txn.commit();
      dbi.close();
    }
  }



  /**
   * @description         Returns iterator of triple item, (pre, on, dig), at each key over all
                          ordinal numbered keys for all prefixes in db. Values are sorted by
                          snKey(pre, on) where on is ordinal number int.
                          Each returned item is triple (pre, on, dig) where pre is identifier prefix,
                          on is ordinal number int and dig is event digest for lookup in .evts sub db.

                            Raises StopIteration Error when empty.
   * @param {*} db  db is opened named sub db with dupsort=False
   * @param {*} key key is key location in db to resume replay, 
   *                If empty then start at first key in database
   */
  getAllOrdItemAllPreIter(db, key = '') {

    console.log("Trying to Open DB===========================")
    const dbi = this.env.openDbi({
      name: db,
    });
    var arr = []
    // console.log("Value of ON = ",on)
    //  key = onKey(pre, on);
    // console.log("Keys are :  ========== ",key.toString())
    const txn = this.env.beginTxn();
    try {
      const cursor = new lmdb.Cursor(txn, dbi, { keyIsBuffer: true });
      const cnt = 0;
      //  let arr = []
      var val;
      let result = false;
      console.log("Value of key ====>", key)
      if (cursor.goToRange(key) == null) {
        console.log("INside coursor go to Range :")
        // do {
        //   cursor.getCurrentNumber((keyParam, data) => {
        //     result = data.slice(7, data.length);
        //   });

        //   yield result;
        //   key = snKey(pre, cnt + 1);
        // } while (cursor.goToNextDup());
        // txn.commit();
        // dbi.close();
        return []
      }
      do {
        cursor.getCurrentBinary((keyParam, data) => {
          result = keyParam;
          val = data;
        });

        console.log("RESULT IS ----------->", result)
        key = splitKeyON(result);
        // console.log("Inside DO ---------------->",key[1], val.toString())
        // console.log("CN and VAL are : ",key[1], val)

        console.log("WE ARE HERE ")
        arr.push([Buffer.from(key[0], 'binary'), key[1], Buffer.from(val, 'binary')])
        // yield [key[1], val]
        console.log(" yield Done ====================>")
        // arr.push({cn : key[1] , val : val})
        // {cn : key[1] , val : val};
      } while (cursor.goToNext() != null);
      return arr
    } catch (error) {
      console.log("ERROR ", error)
      return false;
    } finally {
      console.log("INSIDE FINALLY ====================")
      txn.commit();
      dbi.close();
    }
  }

  /**
     * @description   Return array of values at key in db .Returns empty array if no entry at key

        Duplicates are retrieved in lexocographic order not insertion order.
     * @param {*} db db is opened named sub db with dupsort=True
     * @param {*} key key is bytes of key within sub db's keyspace
     */
  getVals(db, key) {
    try {
      const dbi = this.env.openDbi({
        name: db,
        dupSort: true,

      });
      const txn = this.env.beginTxn();
      const cursor = new lmdb.Cursor(txn, dbi, { keyIsBuffer: true });
      const vals = [];
      let response;
      if (cursor.goToRange(key) != null) {
        for (let found = cursor.goToRange(key); found !== null;
          found = cursor.goToNextDup()) {
          cursor.getCurrentBinary((keyParam, value) => {
            console.log("VALUE :==============", value.toString())
            vals.push(value);
          });
        }
      }

      // if (cursor.goToRange(key) != null) {

      //   do {
      //     cursor.getCurrentBinary((keyParam, data) => {
      //       console.log("data ============>",data.toString())
      //       response = data;
      //     });
      //     vals.push(response) ;
      //   } while (cursor.goToNextDup());
      // }
      txn.commit();
      dbi.close();
      console.log("FINAL VALUE OIS _--------------------->", vals)
      return vals;
    } catch (error) {
      console.log('Error:', error);

      return [];
    }
  }


  /**
* @description Deletes all values at key in db.
    Returns True If key exists in db Else False
* @param {*} db
* @param {*} key
*/

  delVals(db, key) {
    try {
      const dbi = this.env.openDbi({
        name: db,
        dupSort: true,
      });
      const txn = this.env.beginTxn();

      txn.del(dbi, key);

      txn.commit();
      dbi.close();
      return true;
    } catch (error) {
      console.log('ERROR: ', error);
      return false;
    }
  }

  /**
   * @description Return count of dup values at key in db, or zero otherwise

   * @param {*} db db is opened named sub db with dupsort=True
   * @param {*} key key is bytes of key within sub db's keyspace
   */

  cntVals(db, key) {
    const txn = this.env.beginTxn();
    let count = 0;
    try {
      const dbi = this.env.openDbi({
        name: db,
        // create: true,
        dupSort: true,
      });

      console.log("CURSOR INITIALIZED ")
      const cursor = new lmdb.Cursor(txn, dbi, { keyIsBuffer: true });

      if (cursor.goToRange(key) != null) {
        for (let found = (cursor.goToRange(key) === key); found !== null;
          found = cursor.goToNextDup()) {
          cursor.getCurrentBinary(() => {
            count += 1;
          });
        }
      }
      txn.commit();
      dbi.close();
      return count;
    } catch (error) {
      console.log('ERROR =====================:', error);
      return count;
    }
    finally {
      txn.commit();
      // dbi.close();
    }
  }

  /**
   * @description Write each entry from list of bytes vals to key in db
     Adds to existing values at key if any
     Returns True If only one first written val in vals Else False
     Apparently always returns True (is this how .put works with dupsort=True)

     Duplicates are inserted in lexocographic order not insertion order.
     Lmdb does not insert a duplicate unless it is a unique value for that
     key.
   * @param {*} db db is opened named sub db with dupsort=True
   * @param {*} key key is bytes of key within sub db's keyspace
   * @param {*} vals vals is list of bytes of values to be written
   * @returns 
   */
  putVals(db, key, vals) {
    console.log("Opening Database ")
    try {

      const dbi = this.env.openDbi({
        name: db,
        create: true, // will create if database did not exist
        dupSort: true,
      });
      console.log("Database opened and we are here ")
      // const dbi = this.env.openDbi({
      //   name: db,
      //   create: true, // will create if database did not exist
      // dupSort: true,
      // });

      const txn = this.env.beginTxn();


      console.log("About to execute transaction :")
      for (const val in vals) {
        txn.putBinary(dbi, key, vals[val], { keyIsBuffer: true }); //  , noDupData: false
      }
      console.log("Transaction executed :")
      txn.commit();
      dbi.close();
      return true;
    } catch (error) {
      console.log('Error : ', error);
      return false;
    }
  }


  /**
   * @description       Add val bytes as dup to key in db
          Adds to existing values at key if any
          Returns True if written else False if dup val already exists
          Duplicates are inserted in lexocographic order not insertion order.
          Lmdb does not insert a duplicate unless it is a unique value for that
          key.
          Does inclusion test to dectect of duplicate already exists
          Uses a python set for the duplicate inclusion test. Set inclusion scales
          with O(1) whereas list inclusion scales with O(n).
   */

  addVal(db, key, val) {
    let dups = this.getVals(db, key);

    if (dups.length === 0 || dups === false) {
      dups = [];
    }

    const dbi = this.env.openDbi({
      name: db,
      create: true, // will create if database did not exist
      dupSort: true,
    });
    const txn = this.env.beginTxn({ noOverwrite: true });
    console.log("dups.length ==================>", dups.length)
    try {

      let counter;

      if (dups.length === 0) {
        counter = 0;

      } else {
        for (let i = 0; i < dups.length; i++) {
          console.log("Inside for loop", dups[i].toString(), `\n`, val.toString())
          if (dups[i].toString() == val.toString()) {
            break
          } else {
            counter = 1;
          }
        }

      }

      if (counter === 1) {
        txn.putBinary(dbi, key, Buffer.from(val, 'binary'), { overwrite: false, keyIsBuffer: true });
        //    txn.commit();
        //  dbi.close();
        return true
      } else {
        //txn.commit();
        //dbi.close();
        return false
      }

      // this.env.close();
      // return true;
    } catch (error) {
      console.log('ERROR  :', error);
      return false;
    } finally {
      txn.commit();
      dbi.close();
    }
  }



  /**
   * @description         Return list of duplicate values at key in db in insertion order
          Returns empty list if no entry at key
          Removes prepended proem ordinal from each val  before returning
          Assumes DB opened with dupsort=True
    @db db is opened named sub db with dupsort=True
    @key key is bytes of key within sub db's keyspace
   */
  getIoVals(db, key) {

    // const dbi = this.env.openDbi({
    //   name: db,
    //   dupSort: true,
    // });
   
    try {
      var dbi = this.env.openDbi({
        name: db,
        dupSort: true,
      });
      let vals = []
      var txn = this.env.beginTxn(); //{noOverwrite: true}
      const cursor = new lmdb.Cursor(txn, dbi, { keyIsBuffer: true });
      console.log("cursor.goToRange(key) ###################", cursor.goToRange(key))
      if (cursor.goToRange(key) != null) {
          
        do {
          cursor.getCurrentBinary((keyParam, data) => {
        let response = data.slice(33 , data.length);
          console.log("DATA IS = ",data.toString())

          
          vals.push(response)
          });
          
        //  vals.push(response);
        } while (cursor.goToNextDup());
     txn.commit();
      dbi.close();
        return vals
      }else {
        txn.commit();
        dbi.close();
        return []
      }
    } catch (error) {
      console.log("ERROR ================>", error);
      return []
    }
    
    // finally {
    //   txn.commit();
    //   dbi.close();
    // }

  }


    /**
     * @description Return last added dup value at key in db in insertion order
            Returns None no entry at key
            Duplicates are retrieved in insertion order.
            Because lmdb is lexocographic an insertion ordering value is prepended to
            all values that makes lexocographic order that same as insertion order
            Duplicates are ordered as a pair of key plus value so prepending prefix
            to each value changes duplicate ordering. Prefix is 7 characters long.
            With 6 character hex string followed by '.' for a max
            of 2**24 = 16,777,216 duplicates,
     * @param {*} db db is opened named sub db with dupsort=True
     * @param {*} key key is bytes of key within sub db's keyspace
     */
            getIOValsLast(db, key) {
             
          
              try {
                const dbi = this.env.openDbi({
                  name: db,
                  // create: true, // will create if database did not exist
                  dupSort: true,
                });
                const txn = this.env.beginTxn({ readOnly: true });
                const cursor = new lmdb.Cursor(txn, dbi, { keyIsBuffer: true, dupdata: true });
                let vals;
          
               
                try {
                  if(cursor.goToRange(key) != null){
                    cursor.goToLastDup();
                         cursor.getCurrentBinary((keyParam, data) => {
                      vals = data.slice(33, data.length);
                      console.log("data.slice(33, data.length) =============>",(data.slice(33, data.length)).toString());
                  })
                  // for (let found = (cursor.goToKey(key) === key); found !== null;
                  //   found = cursor.goToLastDup()) {
                  //   cursor.getCurrentBinary((keyParam, data) => {
                  //     vals.push(data.slice(33, data.length)) ;
                  //     console.log("data.slice(33, data.length) =============>",(data.slice(33, data.length)).toString());
                  //   });
                  }
                  txn.commit();
                  dbi.close();
                  return vals;
                } catch (error) {
                  txn.commit();
                  dbi.close();
                  return vals;
                }
              } catch (error) {
                console.log('\n\nERROR :', error);
                return null;
              }
            }

              /**
     * @description Return count of dup values at key in db, or zero otherwise
     * @param {*} db db is opened named sub db with dupsort=True
     * @param {*} key key is bytes of key within sub db's keyspace
     */
  cntIoVals(db, key) {
    var dbi = this.env.openDbi({
      name: db,
      create: true, // will create if database did not exist
      dupSort: true,
    });

    var txn = this.env.beginTxn();
   
    try {
     
      const cursor = new lmdb.Cursor(txn, dbi, { keyIsBuffer: true });
      let count = 0;

      if (cursor.goToRange(key)) {
        for (let found = (cursor.goToRange(key) === key); found !== null;
          found = cursor.goToNextDup()) {
          cursor.getCurrentBinary(() => {
            count += 1;
          });
        }
      } else {
        return count;
      }

      //    this.env.close();
      return count;
    } catch (error) {
      console.log('ERROR :', error);
      return false;
    }finally{
      txn.commit();
      dbi.close();
    }
  }

  delIoVals(db, key) {
    var dbi = this.env.openDbi({
      name: db,
    });

    var txn = this.env.beginTxn();
    try {

      // let cursor = new lmdb.Cursor(txn, dbi, { keyIsBuffer: true });

      txn.del(dbi, key);
      // txn.commit();
      // dbi.close();
      // this.env.close();
      return true;
    } catch (error) {
      return false;
    }finally{
      txn.commit();
      dbi.close();
    }
  }


    /**
     * * @description Write each entry from list of bytes vals to key in db in insertion order
            Adds to existing values at key if any
            Returns True If at least one of vals is added as dup, False otherwise
            Duplicates preserve insertion order.
            Because lmdb is lexocographic an insertion ordering value is prepended to
            all values that makes lexocographic order that same as insertion order
            Duplicates are ordered as a pair of key plus value so prepending prefix
            to each value changes duplicate ordering. Prefix is 7 characters long.
            With 6 character hex string followed by '.' for a max
            of 2**24 = 16,777,216 duplicates. With prepended ordinal must explicity
            check for duplicate values before insertion. Uses a python set for the
            duplicate inclusion test. Set inclusion scales with O(1) whereas list
            inclusion scales with O(n).
     * @param {*} db   db is opened named sub db with dupsort=False
     * @param {*} key key is bytes of key within sub db's keyspace
     * @param {*} val val is bytes of value to be written
     */
  putIOVals(db, key, vals) {
              let dups = this.getIOValues(db, key);
          
              if (dups.toString() === 'false') {
                dups = [];
              }
      //   console.log("dups ===============>",dups[0].toString(), dups[1].toString(),dups[2].toString(),dups[3].toString(),dups[4].toString())
              try {
                const dbi = this.env.openDbi({
                  name: db,
                  create: true, // will create if database did not exist
                dupSort: true,
                });
          
                const txn = this.env.beginTxn({keyIsBuffer: true, noDupData : false });
                const cursor = new lmdb.Cursor(txn, dbi, { keyIsBuffer: true });
                let count = 0;
                // let result = false;
                let response = null;
                let countPad = 0;
                console.log("Range Exists========================",cursor.goToRange(key))
                if (cursor.goToRange(key) != null) {
                  
                  if(cursor.goToLastDup()){
                    count = 1 + parseInt((cursor.getCurrentBinary()).slice(31,32))                       //((cursor.getCurrentBinary()).slice(31,32))
                    console.log("VALUE OF COUNT PAD IS = ",count)
                  }


                } 
                for (let val in vals){
                  console.log("VALUE OF DUP IS ", vals[val])
                 console.log("DUP contains or not ?=====================>")
                  if(!(Buffer.concat(dups)).includes(vals[val])){
                 //   val = (b'%032x.' % (idx)) +  val  # prepend ordering proem
                 countPad = pad(count, 32);
                 console.log("COuntpad after paddding is ==================>",countPad)
                 countPad += '.';
                  // val = [Buffer.from(countPad, 'binary'), Buffer.from(vals[val], 'binary')];
                  console.log("vals[val] ===================>",vals[val])
                 val = Buffer.concat([Buffer.from(countPad,'binary') , vals[val]])
                 console.log("Value to be input is ",val.toString())
                 txn.putBinary(dbi, key, val);  // noOverwrite: true  , { keyIsBuffer: true }
                 count += 1;
                 response = true
                  }else{

                    response =  false 
                  }
                }
                txn.commit();
                dbi.close();
                return response;
              } catch (error) {
                console.log('ERROR:', error);
                return false;
              }
            }
   
              /**
     * @description Return list of values associated with a key in db (in insertion order)
     * returns empty  if there is no key . Duplicates are retrieved in insertion order.
     * lmdb is lexocographic an insertion ordering value is prepended to
           all values that makes lexocographic order that same as insertion order
            Duplicates are ordered as a pair of key plus value so prepending prefix
           to each value changes duplicate ordering. Prefix is 7 characters long.
           With 6 character hex string followed by '.' for a max
           of 2**24 = 16,777,216 duplicates,
     *
     */

  getIOValues(db, key) {
    try {
      const dbi = this.env.openDbi({
        name: db,
        dupSort: true,
      });

      const txn = this.env.beginTxn({ buffers: true });
      const cursor = new lmdb.Cursor(txn, dbi, { keyIsBuffer: true });
      const valsArray = [];
      const keyArray = [];
      if (cursor.goToRange(key)) {
        for (let found = (cursor.goToRange(key) === key); found !== null;
          found = cursor.goToNextDup()) {
          cursor.getCurrentBinary((keyParam, data) => {
            this.data = data;
            console.log("data String is -==========================>",(this.data.slice(33, this.data.length)).toString())
            this.data = this.data.slice(33, this.data.length);
            keyArray.push(keyParam);
            valsArray.push(this.data);
          });
        }
      }

      txn.commit();
      dbi.close();
      return valsArray;
    } catch (error) {
      console.log(' ERROR :', error);
      return false;
    }
  }


/**
 * @description : Add val bytes as dup in insertion order to key in db
                          Adds to existing values at key if any
                          Returns True if written else False if val is already a dup
                          Actual value written include prepended proem ordinal
                          Assumes DB opened with dupsort=True

 * @param {*} db  db is opened named sub db with dupsort=False
 * @param {*} key key is bytes of key within sub db's keyspace
 * @param {*} vals  val is bytes of value to be written
 */
  addIoVal(db, key, vals) {

    return this.putIOVals(db, key, vals)
  }



/**
 * description         Deletes dup io val at key in db. Performs strip search to find match.
        Strips proems and then searches.
        Returns True if delete else False if val not present
        Assumes DB opened with dupsort=True

        Duplicates at a given key preserve insertion order of duplicate.
        Because lmdb is lexocographic an insertion ordering proem is prepended to
        all values that makes lexocographic order that same as insertion order
        Duplicates are ordered as a pair of key plus value so prepending proem
        to each value changes duplicate ordering. Proem is 33 characters long.
        With 32 character hex string followed by '.' for essentially unlimited
        number of values which will be limited by memory.

        Does a linear search so not very efficient when not deleting from the front.
        This is hack for supporting escrow which needs to delete individual dup.
        The problem is that escrow is not fixed buts stuffs gets added and
        deleted which just adds to the value of the proem. 2**16 is an impossibly
        large number so the proem will not max out practically. But its not
        and elegant solution. So maybe escrows need to use a different approach.
        But really didn't want to add another database just for escrows.


 * @param {*} db   db is opened named sub db with dupsort=False
 * @param {*} key  key is bytes of key within sub db's keyspace
 * @param {*} val  val is bytes of value to be deleted without intersion ordering proem
 * @returns 
 */
  delIoVal(db, key, val) {
    var dbi = this.env.openDbi({
      name: db,
    });

    var txn = this.env.beginTxn();
    var cursor = new lmdb.Cursor(txn, dbi, { keyIsBuffer: true });
    try {

      if(cursor.goToRange(key) != null){
        do {
          cursor.getCurrentBinary((keyParam, data) => {
              console.log("data.slice(33 , data.length) --------------->", data.slice(33 , data.length) , '\n', val , '\n', (data.length) == val)
           if(Buffer.compare(data.slice(33 , data.length) , val)){
             
             cursor.del();
             
           }
          });

        } while (cursor.goToNextDup());
        
      }

      // txn.commit();
      // dbi.close();
      // this.env.close();
      return true;
    } catch (error) {
      console.log("ERROR  ======================>",error)
      return false;
    }finally{
      txn.commit();
      dbi.close();
    }
  }
          


  /**
   * @description Returns iterator of all dup vals in insertion order for all entries
                  with same prefix across all sequence numbers in order without gaps
                  starting with zero. Stops if gap or different pre.
                  Assumes that key is combination of prefix and sequence number given
                  by .snKey().
                  Removes prepended proem ordinal from each val before returning

                  Raises StopIteration Error when empty.

                  Duplicates are retrieved in insertion order.

   * @param {*} db  db is opened named sub db with dupsort=True
   * @param {*} pre pre is bytes of itdentifier prefix prepended to sn in key
                     within sub db's keyspace
   */
  getIoValsAllPreIter(db, pre){

    var dbi = this.env.openDbi({
      name: db,
      dupSort:true ,
    });
    console.log("INSIDE getIoValsAllPreIter ===================>")
try{    var txn = this.env.beginTxn();
    var cursor = new lmdb.Cursor(txn, dbi, { keyIsBuffer: true });
    let cnt = 0
   let key = snKey(pre, cnt)
   do {
    cursor.getCurrentBinary((keyParam, data) => {
      console.log("VAUE OF DATA : ",data)
      response = data.slice(33 , data.length);;
      console.log("VALUE OF RESPONSE IS ##########################################>");
    });
    arr.push(response);
    key = snKey(pre, cnt+1)
   

  } while (cursor.goToNextDup());

  txn.commit();
  dbi.close();
  return arr;
}catch (error) {
  console.log("getValsIter  ERROR IS =====================+", error)
  return false;
}
    
  }

  // def getKelIter(self, pre):
  // """
  // Returns iterator of all dup vals in insertion order for all entries
  // with same prefix across all sequence numbers without gaps. Stops if
  // encounters gap.
  // Assumes that key is combination of prefix and sequence number given
  // by .snKey().

  // Raises StopIteration Error when empty.
  // Duplicates are retrieved in insertion order.
  // db is opened as named sub db with dupsort=True

  // Parameters:
  //     pre is bytes of itdentifier prefix prepended to sn in key
  //         within sub db's keyspace
  // """
  // if hasattr(pre, "encode"):
  //     pre = pre.encode("utf-8")  # convert str to bytes
  // return self.getIoValsAllPreIter(self.kels, pre)


  /**
   * @description   Returns iterator of all dup vals in insertion order for all entries
                    with same prefix across all sequence numbers without gaps. Stops if
                    encounters gap.
                    Assumes that key is combination of prefix and sequence number given
                    by .snKey().

                    Raises StopIteration Error when empty.
                    Duplicates are retrieved in insertion order.
                    db is opened as named sub db with dupsort=True

   * @param {*} pre pre is bytes of itdentifier prefix prepended to sn in key
   */
  getKelIter(pre){

        pre = Buffer.from(pre, 'binary');
        return this.getIoValsAllPreIter(this.kels, pre);

  }
}


/**
 * 
 * @param {string} baseDirPath  db directory path
 * @param {int} port  db port 
 */
function setupDbEnv(baseDirPath = '', port = 8080) {

  if (!baseDirPath)
    baseDirPath = DATABASE_DIR_PATH + port
  baseDirPath = path.resolve(resolveHome(baseDirPath))
  if (!fs.pathExistsSync(baseDirPath)) {
    try {
      fs.mkdirsSync(baseDirPath, 0o777)
    } catch (e) {
      baseDirPath = ALT_DATABASE_DIR_PATH + port
      baseDirPath = path.resolve(resolveHome(baseDirPath))
      if (!fs.pathExistsSync(baseDirPath)) {
        fs.mkdirsSync(baseDirPath, 0o777)
      }
    }
  } else {
    if (fs.accessSync(baseDirPath, fs.constants.F_OK | fs.constants.W_OK | fs.constants.R_OK)) {
      baseDirPath = ALT_DATABASE_DIR_PATH + port
      baseDirPath = path.resolve(resolveHome(baseDirPath))
      if (!fs.pathExistsSync(baseDirPath)) { fs.mkdirsSync(baseDirPath, 0o777) }
    }
  }
  keriDbDirPath = baseDirPath  // set global db directory path
  lmdb.open(keriDbDirPath, {
    dbName: DB_KEY_EVENT_LOG_NAME
  })


}
/**
 * 
 * @param {String} filepath 
 * @description This method will resolve file path starting with tilda '~'
 */

function resolveHome(filepath) {
  if (filepath[0] === '~') {
    return path.join(process.env.HOME, filepath.slice(1));
  }
  return filepath;
}


/**
 * @description  Wrapper to enable temporary (test) Databaser instances
    When used in with statement calls .clearDirPath() on exit of with block
 * @param {} name name is str name of temporary Databaser dirPath  extended name so
                 can have multiple temporary databasers is use differen name
 * @param {*} cls cls is Class instance of subclass instance
 */
function* openLmdber(name = 'test', cls = null) {
  if (!cls) {
    cls = new LMDBer(null, name, true);
  }
  try {
    // databaser = cls
    yield cls;
  } catch (error) {
    console.log("INSIDE CLS ERROR")
    throw new Error(error);
  }
}

function openLmbd(name = 'test') {
  return openLmdber(name, new LMDBer());
}

module.exports = { openLmbd, LMDBer }
