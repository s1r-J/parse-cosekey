import { test } from 'tap';
import crypto from 'crypto';
import str2ab from 'str2ab';
import KeyParser from '../dist/keyParser';
import verifier from '../dist/verifier';

test('# Verify with COSE', function (t) {
  t.test('## ES256', function (t) {
    try {
      // const privJWK = {
      //   kty: 'EC',
      //   alg: 'ES256',
      //   crv: 'P-256',
      //   d: '870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE',
      // };
      const privateKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg870MB6gfuTJ4HtUn
UvYMyJpr5eUZNP4Bk43bVdj3eAGhRANCAAQwoEJM0hwpRIOKLXXJKzfnbqINnwCJ
OjtO7oo8Cq/sPuBLZekkVtmIi1Kzeb371R7oae8fD8ZbZllpW2zOCBcj
-----END PRIVATE KEY-----`;
      const pubJWK = {
        kty: 'EC',
        alg: 'ES256',
        crv: 'P-256',
        x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
        y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
      };
      const cose = KeyParser.jwk2cose(pubJWK);

      const data = str2ab.string2buffer('test data to sign');
      const sign = crypto.createSign('sha256').update(data);
      const signature = sign.sign(privateKey);

      const result = verifier.verifyWithCOSEKey(data, signature, cose);
      t.ok(result);
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## ES256K', function (t) {
    try {
      const privateKey = `-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgRo2gC67q1qWSZ+nkpHAT
s6PPNqRlwK2+CPBiV93LxkqhRANCAATL774LU/mIvAz2AeDZe4eOgpa+ogwkWJIn
/+a6SLlE37ieXsQ36hOfcfhViailtucG9bSuqMFEnQi6VvgH+WTf
-----END PRIVATE KEY-----
`;

      const cose = new Map<number, any>()
        .set(1, 2)
        .set(-1, 8)
        .set(3, -47)
        .set(
          -2,
          Buffer.from([
            0xcb, 0xef, 0xbe, 0x0b, 0x53, 0xf9, 0x88, 0xbc, 0x0c, 0xf6, 0x01, 0xe0, 0xd9, 0x7b, 0x87, 0x8e, 0x82, 0x96,
            0xbe, 0xa2, 0x0c, 0x24, 0x58, 0x92, 0x27, 0xff, 0xe6, 0xba, 0x48, 0xb9, 0x44, 0xdf,
          ]),
        )
        .set(
          -3,
          Buffer.from([
            0xb8, 0x9e, 0x5e, 0xc4, 0x37, 0xea, 0x13, 0x9f, 0x71, 0xf8, 0x55, 0x89, 0xa8, 0xa5, 0xb6, 0xe7, 0x06, 0xf5,
            0xb4, 0xae, 0xa8, 0xc1, 0x44, 0x9d, 0x08, 0xba, 0x56, 0xf8, 0x07, 0xf9, 0x64, 0xdf,
          ]),
        );

      const data = str2ab.string2buffer('test data to sign');
      const sign = crypto.createSign('sha256').update(data);
      const signature = sign.sign(privateKey);

      const result = verifier.verifyWithCOSEKey(data, signature, cose);
      t.ok(result);
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.end();
});

test('# Verify with JWK', function (t) {
  t.test('## ES256', function (t) {
    try {
      // const privJWK = {
      //   kty: 'EC',
      //   alg: 'ES256',
      //   crv: 'P-256',
      //   d: '870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE',
      // };
      const privateKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg870MB6gfuTJ4HtUn
UvYMyJpr5eUZNP4Bk43bVdj3eAGhRANCAAQwoEJM0hwpRIOKLXXJKzfnbqINnwCJ
OjtO7oo8Cq/sPuBLZekkVtmIi1Kzeb371R7oae8fD8ZbZllpW2zOCBcj
-----END PRIVATE KEY-----`;
      const pubJWK = {
        kty: 'EC',
        alg: 'ES256',
        crv: 'P-256',
        x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
        y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
      };

      const data = str2ab.string2buffer('test data to sign');
      const sign = crypto.createSign('sha256').update(data);
      const signature = sign.sign(privateKey);

      const result = verifier.verifyWithJWK(data, signature, pubJWK);
      t.ok(result);
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.end();
});

test('# Verify with PEM', function (t) {
  t.test('## RS256', function (t) {
    try {
      const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem',
        },
        privateKeyEncoding: {
          type: 'pkcs1',
          format: 'pem',
        },
      });

      const data = str2ab.string2buffer('test data to sign');
      const sign = crypto.createSign('sha256').update(data);
      const signature = sign.sign(privateKey);

      const result = verifier.verifyWithPEM(data, signature, publicKey, 'RS256');
      t.ok(result);
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## RS512', function (t) {
    try {
      const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem',
        },
        privateKeyEncoding: {
          type: 'pkcs1',
          format: 'pem',
        },
      });

      const data = str2ab.string2buffer('test data to sign');
      const sign = crypto.createSign('sha512').update(data);
      const signature = sign.sign(privateKey);

      const result = verifier.verifyWithPEM(data, signature, publicKey, 'RS512');
      t.ok(result);
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## ES256K', function (t) {
    try {
      const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'secp256k1',
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem',
        },
        privateKeyEncoding: {
          type: 'sec1',
          format: 'pem',
        },
      });

      const data = str2ab.string2buffer('test data to sign');
      const sign = crypto.createSign('sha256').update(data);
      const signature = sign.sign(privateKey);

      const result = verifier.verifyWithPEM(data, signature, publicKey, 'ES256K');
      t.ok(result);
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.end();
});
