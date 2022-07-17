# parse-cosekey

[![npm version](https://badge.fury.io/js/parse-cosekey.svg)](https://badge.fury.io/js/parse-cosekey) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Build Status](https://app.travis-ci.com/s1r-J/parse-cosekey.svg?branch=main)](https://app.travis-ci.com/s1r-J/parse-cosekey) [![Coverage Status](https://coveralls.io/repos/github/s1r-J/parse-cosekey/badge.svg?branch=main)](https://coveralls.io/github/s1r-J/parse-cosekey?branch=main)

Parse COSE(CBOR Object Signing and Encryption) to JWK(JSON Web Key) or PEM.

## Description

WebAuthn and FIDO2 requires converting COSE(CBOR Object Signing and Encryption, [RFC 8152](https://datatracker.ietf.org/doc/html/rfc8152)) into JWK(JSON Web Key, [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)) or PEM.

This module helps programmers to conversion between COSE, JWK and PEM.

## Install

[npm](https://www.npmjs.com/package/parse-cosekey)

```
npm install parse-cosekey
```

## Usage

### import / require

```js
import cosekey from 'parse-cosekey';
// const cosekey = require('parse-cosekey'); // if you use CommonJS

const jwk = cosekey.KeyParser.cose2jwk(coseMap);
```

### How to parse key

This module's most used class is [KeyParser](https://github.com/s1r-J/parse-cosekey/blob/main/src/keyParser.ts) that parses key.

#### COSE <-> JWK

```js
import cosekey from 'parse-cosekey';

const coseMap = new Map<number, any>()
    .set(1, 2)
    .set(3, -7)
    .set(-1, 1)
    .set(
      -2,
      Buffer.from([
        0xe7, 0x64, 0xeb, 0xad, 0x3b, 0xf0, 0x03, 0x87, 0x46, 0x99, 0xb7, 0xc5, 0x41, 0xce, 0x94, 0x79, 0x6a, 0x17, 0xac, 0xd6, 0x53, 0xeb, 0x58, 0x28, 0xba, 0x2f, 0x40, 0xa3, 0xe3, 0x4b, 0xf7, 0xdb,
      ]),
    )
    .set(
      -3,
      Buffer.from([
        0x93, 0xc3, 0xdf, 0xd7, 0x10, 0xee, 0x2c, 0xb4, 0x43, 0x4e, 0x27, 0xd5, 0x42, 0x50, 0x2e, 0x82, 0xef, 0x5f, 0x2c, 0xa0, 0xef, 0xe8, 0xde, 0xd8, 0x1d, 0xce, 0x9d, 0xad, 0xbc, 0x1a, 0x40, 0x2c,
      ]),
    );
const jwk = cosekey.KeyParser.cose2jwk(coseMap);
// {
//   kty: 'EC',
//   alg: 'ES256',
//   crv: 'P-256',
//   x: '52TrrTvwA4dGmbfFQc6UeWoXrNZT61goui9Ao-NL99s',
//   y: 'k8Pf1xDuLLRDTifVQlAugu9fLKDv6N7YHc6drbwaQCw'
// }
```

You can also parse JWK to COSE using [KeyParser#jwk2cose](https://www.s1r-j.tk/parse-cosekey/classes/keyParser.default.html#jwk2cose).

#### JWK -> PEM

```js
import cosekey from 'parse-cosekey';

const jwk = {
  kty: 'EC',
  alg: 'ES256',
  crv: 'P-256',
  x: Buffer.from([
    0xe7, 0x64, 0xeb, 0xad, 0x3b, 0xf0, 0x03, 0x87, 0x46, 0x99, 0xb7, 0xc5, 0x41, 0xce, 0x94, 0x79, 0x6a, 0x17, 0xac,
    0xd6, 0x53, 0xeb, 0x58, 0x28, 0xba, 0x2f, 0x40, 0xa3, 0xe3, 0x4b, 0xf7, 0xdb,
  ]),
  y: Buffer.from([
    0x93, 0xc3, 0xdf, 0xd7, 0x10, 0xee, 0x2c, 0xb4, 0x43, 0x4e, 0x27, 0xd5, 0x42, 0x50, 0x2e, 0x82, 0xef, 0x5f, 0x2c,
    0xa0, 0xef, 0xe8, 0xde, 0xd8, 0x1d, 0xce, 0x9d, 0xad, 0xbc, 0x1a, 0x40, 0x2c,
  ]),
};
const pem = await cosekey.KeyParser.jwk2pem(jwk);
// -----BEGIN PUBLIC KEY-----
// MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE52TrrTvwA4dGmbfFQc6UeWoXrNZT
// 61goui9Ao+NL99uTw9/XEO4stENOJ9VCUC6C718soO/o3tgdzp2tvBpALA==
// -----END PUBLIC KEY-----
```

You can also parse PEM to JWK using [KeyParser#pem2jwk](https://www.s1r-j.tk/parse-cosekey/classes/keyParser.default.html#pem2jwk).

#### COSE -> PEM

Directly parse COSE to PEM.

```js
import cosekey from 'parse-cosekey';

const coseMap = new Map<number, any>()
    .set(1, 2)
    .set(3, -7)
    .set(-1, 1)
    .set(
      -2,
      Buffer.from([
        0xe7, 0x64, 0xeb, 0xad, 0x3b, 0xf0, 0x03, 0x87, 0x46, 0x99, 0xb7, 0xc5, 0x41, 0xce, 0x94, 0x79, 0x6a, 0x17,
        0xac, 0xd6, 0x53, 0xeb, 0x58, 0x28, 0xba, 0x2f, 0x40, 0xa3, 0xe3, 0x4b, 0xf7, 0xdb,
      ]),
    )
    .set(
      -3,
      Buffer.from([
        0x93, 0xc3, 0xdf, 0xd7, 0x10, 0xee, 0x2c, 0xb4, 0x43, 0x4e, 0x27, 0xd5, 0x42, 0x50, 0x2e, 0x82, 0xef, 0x5f,
        0x2c, 0xa0, 0xef, 0xe8, 0xde, 0xd8, 0x1d, 0xce, 0x9d, 0xad, 0xbc, 0x1a, 0x40, 0x2c,
      ]),
    );
const pem = await cosekey.KeyParser.cose2pem(coseMap);
// -----BEGIN PUBLIC KEY-----
// MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE52TrrTvwA4dGmbfFQc6UeWoXrNZT
// 61goui9Ao+NL99uTw9/XEO4stENOJ9VCUC6C718soO/o3tgdzp2tvBpALA==
// -----END PUBLIC KEY-----
```

Of course you can parse PEM to COSE using [KeyParser#pem2cose](https://www.s1r-j.tk/parse-cosekey/classes/keyParser.default.html#pem2cose).

More details see [API Reference](#api-reference)

### Verify

This module provide Verifier class to verify data using signature and key(COSE, JWK or PEM).

#### COSE

```js
import cosekey from 'parse-cosekey';

const data = Buffer.from([0xaa, 0xbb, 0xcc]);
const signature = Buffer.from([0x11, 0x22, 0x33]);
const cose = new Map<number, any>()
    .set(1, 2)
    .set(3, -7)
    .set(-1, 1)
    .set(
      -2,
      Buffer.from([0xaa, 0xbb, 0xcc]),
    )
    .set(
      -3,
      Buffer.from([0x11, 0x22, 0x33]),
    );
const result = await cosekey.Verifier.verifyWithCOSEKey(data, signature, cose);
```

#### JWK

```js
import cosekey from 'parse-cosekey';

const data = Buffer.from([0xaa, 0xbb, 0xcc]);
const signature = Buffer.from([0x11, 0x22, 0x33]);
const jwk = {
  kty: 'EC',
  alg: 'ES256',
  crv: 'P-256',
  x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
  y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
};
const result = await cosekey.Verifier.verifyWithJWK(data, signature, jwk);
```

#### PEM

```js
import cosekey from 'parse-cosekey';

const data = Buffer.from([0xaa, 0xbb, 0xcc]);
const signature = Buffer.from([0x11, 0x22, 0x33]);
const pem = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE52TrrTvwA4dGmbfFQc6UeWoXrNZT
61goui9Ao+NL99uTw9/XEO4stENOJ9VCUC6C718soO/o3tgdzp2tvBpALA==
-----END PUBLIC KEY-----
`;
const result = await cosekey.Verifier.verifyWithPEM(data, signature, pem);
```

### API Reference

API reference is published on GitHub Pages.

URL: https://s1r-j.github.io/parse-cosekey/

## Alternatives

- [pem-jwk](https://www.npmjs.com/package/pem-jwk)
- [jwk-to-pem](https://www.npmjs.com/package/jwk-to-pem)
- [jose](https://www.npmjs.com/package/jose)
- [cose-to-jwk](https://www.npmjs.com/package/cose-to-jwk)

## License

[Apache-2.0](http://www.apache.org/licenses/LICENSE-2.0.html)

## Author

[s1r-J](https://github.com/s1r-J)
