# parse-cosekey

[![npm version](https://badge.fury.io/js/parse-cosekey.svg)](https://badge.fury.io/js/parse-cosekey) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Parse COSE(CBOR Object Signing and Encryption) to JWK(JSON Web Key) or PEM.

## Description

WebAuthn and FIDO2 requires converting COSE(CBOR Object Signing and Encryption, [RFC 8152](https://datatracker.ietf.org/doc/html/rfc8152)) into JWK(JSON Web Key, [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)) or PEM.

This module helps programmers to conversion between COSE, JWK and PEM .

## Alternatives

- [pem-jwk - npm](https://www.npmjs.com/package/pem-jwk)
- [jwk-to-pem - npm](https://www.npmjs.com/package/jwk-to-pem)
- [jose - npm](https://www.npmjs.com/package/jose)
- [cose-to-jwk - npm](https://www.npmjs.com/package/cose-to-jwk)

## Install

[npm](https://www.npmjs.com/package/parse-cosekey)

```
npm install parse-cosekey
```

## Usage

### Module

#### ESM

```js
import cosekey from 'parse-cosekey';

const jwk = cosekey.KeyParser.cose2jwk(coseMap);
```

#### CJS

```js
const cosekey = require('parse-cosekey');

const jwk = cosekey.KeyParser.cose2jwk(coseMap);
```

### API Reference

https://s1r-j.github.io/parse-cosekey/

## License

[Apache-2.0](http://www.apache.org/licenses/LICENSE-2.0.html)

## Author

[s1r-J](https://github.com/s1r-J)
