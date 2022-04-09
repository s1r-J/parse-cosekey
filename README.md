# parse-cosekey

Parse COSE(CBOR Object Signing and Encryption) to JWK(JSON Web Key) or PEM.

## Description

This module does not test enough. If you want reliability, I recommend you to using other modules as follows.
However I am glad that you use this module and contribute in some way (as reporting issue or pull request).

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

## Licence

[Apache-2.0](http://www.apache.org/licenses/LICENSE-2.0.html)

## Author

[s1r-J](https://github.com/s1r-J)
