# KERI IMPLEMENTATION

    This library is the js version of keri .


## How to run test cases

Step:1

Go inside folder 
tests/core

Run command:
~~~~
node  test_coring.js
~~~~

To do Blake3 testing : 

Edit test_coring.js file and replace **testslibsodium()**  with **blake()**

Save file and than run Command

~~~~
node  test_coring.js
~~~~




Dependencies
Binaries
NOde packages DEPENDENCIES 
 "bignum": "^0.13.1",
    "blake3": "^2.1.4",
    "blakejs": "^1.1.1",
    "blob": "^0.1.0",
    "bytearray-node": "^3.2.8",
    "cbor": "^5.1.0",
    "collections": "^5.1.11",
    "filereader": "^0.10.3",
    "fs-extra": "^9.0.1",
    "hash-wasm": "^4.9.0",
    "jest-sonar-reporter": "^2.0.0",
    "js-base64": "^2.5.2",
    "libsodium-wrappers-sumo": "^0.7.6",
    "lmdb-store": "^0.3.21",
    "lodash": "^4.17.21",
    "msgpack5": "^4.5.1",
    "multi-regexp2": "git+https://github.com/valoricDe/MultiRegExp2.git",
    "node-lmdb": "^0.9.4",
    "nodemon": "^2.0.7",
    "tmp": "^0.2.1",
    "url-safe-base64": "^1.1.1",
    "urlsafe-base64": "^1.0.0",
    "utf8": "^3.0.0",
    "util": "^0.12.3",
    "xregexp": "^4.4.0"

USE COMMAND TO INSTALL ALL THE MODULES 
$ npm install 


Development
Setup
Ensure Python 3.9 is present along with venv and dev header files;
Setup virtual environment: python3 -m venv keripy
Activate virtual environment: source keripy/bin/activate
Setup dependencies: pip install -r requirements.txt
Testing
Install pytest: pip install pytest

Run the test suites:

pytest tests/ --ignore tests/demo/
pytest tests/demo/