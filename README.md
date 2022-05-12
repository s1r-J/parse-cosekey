# parse-cosekey

Parse COSE(CBOR Object Signing and Encryption) to JWK(JSON Web Key) or PEM.

## Description

WebAuthn and FIDO2 requires converting COSE(CBOR Object Signing and Encryption, [RFC 8152](https://datatracker.ietf.org/doc/html/rfc8152)) into JWK(JSON Web Key, [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)) or PEM.

This module helps programmers to convert converting.

## Alternatives

- [pem-jwk - npm](https://www.npmjs.com/package/pem-jwk)
- [jwk-to-pem - npm](https://www.npmjs.com/package/jwk-to-pem)
- [jose - npm](https://www.npmjs.com/package/jose)
- [cose-to-jwk - npm](https://www.npmjs.com/package/cose-to-jwk)

## Install

```
npm install parse-cosekey
```

### ESM

```js
import cosekey from 'parse-cosekey';

const jwk = cosekey.KeyParser.cose2jwk(coseMap);
```

### CJS

```js
const cosekey = require('parse-cosekey');

const jwk = cosekey.KeyParser.cose2jwk(coseMap);
```

## License

[Apache-2.0](http://www.apache.org/licenses/LICENSE-2.0.html)

## Author

[s1r-J](https://github.com/s1r-J)
