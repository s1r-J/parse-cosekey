import { test } from 'tap';
import crypto from 'crypto';
import str2ab from 'str2ab';
import KeyParser from '../dist/keyParser';

const COSE_MAP = new Map<number, any>();
COSE_MAP.set(1, 2)
  .set(3, -7)
  .set(-1, 1)
  .set(
    -2,
    Buffer.from([
      0xe7, 0x64, 0xeb, 0xad, 0x3b, 0xf0, 0x03, 0x87, 0x46, 0x99, 0xb7, 0xc5, 0x41, 0xce, 0x94, 0x79, 0x6a, 0x17, 0xac,
      0xd6, 0x53, 0xeb, 0x58, 0x28, 0xba, 0x2f, 0x40, 0xa3, 0xe3, 0x4b, 0xf7, 0xdb,
    ]),
  )
  .set(
    -3,
    Buffer.from([
      0x93, 0xc3, 0xdf, 0xd7, 0x10, 0xee, 0x2c, 0xb4, 0x43, 0x4e, 0x27, 0xd5, 0x42, 0x50, 0x2e, 0x82, 0xef, 0x5f, 0x2c,
      0xa0, 0xef, 0xe8, 0xde, 0xd8, 0x1d, 0xce, 0x9d, 0xad, 0xbc, 0x1a, 0x40, 0x2c,
    ]),
  );

const JWK = {
  kty: 'EC',
  alg: 'ES256',
  crv: 'P-256',
  x: str2ab.base642buffer('52TrrTvwA4dGmbfFQc6UeWoXrNZT61goui9Ao+NL99s='),
  y: str2ab.base642buffer('k8Pf1xDuLLRDTifVQlAugu9fLKDv6N7YHc6drbwaQCw='),
};

const PEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE52TrrTvwA4dGmbfFQc6UeWoXrNZT
61goui9Ao+NL99uTw9/XEO4stENOJ9VCUC6C718soO/o3tgdzp2tvBpALA==
-----END PUBLIC KEY-----`;

const ATTESTATION_OBJECT = str2ab.base64url2buffer(
  'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhAP8GpebSNIp6hRSWD0C5-Rby7WaGEqqqilyfmwxKd8hvAiEAr2-HMPgLjTA7VgNpvh32xdsmXAf-cbJBgG1Hv3UtVENjeDVjgVkB3zCCAdswggF9oAMCAQICAQEwDQYJKoZIhvcNAQELBQAwYDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCENocm9taXVtMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMRowGAYDVQQDDBFCYXRjaCBDZXJ0aWZpY2F0ZTAeFw0xNzA3MTQwMjQwMDBaFw00MTEyMDExNTIxMTRaMGAxCzAJBgNVBAYTAlVTMREwDwYDVQQKDAhDaHJvbWl1bTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEaMBgGA1UEAwwRQmF0Y2ggQ2VydGlmaWNhdGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASNYX5lyVCOZLzFZzrIKmeZ2jwURmgsJYxGP__fWN_S-j5sN4tT15XEpN_7QZnt14YvI6uvAgO0uJEboFaZlOEBoyUwIzATBgsrBgEEAYLlHAIBAQQEAwIFIDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA0kAMEYCIQCvDWiYl9lric6PkfYkH812bRT6UyMZ0QruejnnoK2X2gIhALkk2RmA8ZTXFtX3hpFt46nKGSmK5llg59g38u062C5WaGF1dGhEYXRhWKR0puqSE8mcL3SyJJKzIM9AJiqUwalQoDl_KSULYIQe8EUAAAABAQIDBAUGBwgBAgMEBQYHCAAgLAZo3VcNKR1y2xRLmEhbKYeOAo4zmr3pIzhZne9s0MSlAQIDJiABIVgg52TrrTvwA4dGmbfFQc6UeWoXrNZT61goui9Ao-NL99siWCCTw9_XEO4stENOJ9VCUC6C718soO_o3tgdzp2tvBpALA',
);

test('# cose <-> jwk', function (t) {
  t.test('## cose -> jwk', function (t) {
    try {
      const jwk = KeyParser.cose2jwk(COSE_MAP);
      t.same(jwk, {
        ...JWK,
        x: str2ab.buffer2base64url(JWK.x),
        y: str2ab.buffer2base64url(JWK.y),
      });
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## jwk -> cose', function (t) {
    try {
      const cose = KeyParser.jwk2cose(JWK);
      t.same(cose, COSE_MAP);
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

test('# cose <-> pem', function (t) {
  t.test('## cose -> pem', async function (t) {
    try {
      const pem = await KeyParser.cose2pem(COSE_MAP);
      t.same(pem.replace(/(\n|\r|\r\n)+/g, ''), PEM.replace(/(\n|\r|\r\n)+/g, ''));
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## pem -> cose', async function (t) {
    try {
      const coseMap = await KeyParser.pem2cose(PEM, 'ES256');
      t.same(coseMap, COSE_MAP);
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

test('# jwk <-> pem', function (t) {
  t.test('## jwk -> pem', async function (t) {
    try {
      const pem = await KeyParser.cose2pem(COSE_MAP);
      t.same(pem.replace(/(\n|\r|\r\n)+/g, ''), PEM.replace(/(\n|\r|\r\n)+/g, ''));
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## pem -> jwk', async function (t) {
    try {
      const jwk = await KeyParser.pem2jwk(PEM);

      const expected = {
        kty: JWK.kty,
        crv: JWK.crv,
        x: str2ab.buffer2base64url(JWK.x),
        y: str2ab.buffer2base64url(JWK.y),
      };
      t.same(jwk, expected);
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

test('# attestationObject -> jwk', function (t) {
  t.test('## attestationObject -> jwk', function (t) {
    try {
      const jwk = KeyParser.attestationObject2jwk(ATTESTATION_OBJECT);
      t.same(jwk, {
        ...JWK,
        x: str2ab.buffer2base64url(JWK.x),
        y: str2ab.buffer2base64url(JWK.y),
      });
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

test('# der <-> pem', function (t) {
  t.test('## publickey pem -> der', async function (t) {
    try {
      const keys = crypto.generateKeyPairSync('rsa', {
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
      const expected = crypto.createPublicKey(keys.publicKey).export({
        type: 'spki',
        format: 'der',
      });

      const der = KeyParser.pem2der(keys.publicKey);
      t.same(der, expected);
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## privatekey pem -> der', async function (t) {
    try {
      const keys = crypto.generateKeyPairSync('rsa', {
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
      const expected = crypto.createPrivateKey(keys.privateKey).export({
        type: 'pkcs1',
        format: 'der',
      });

      const der = KeyParser.pem2der(keys.privateKey);
      t.same(der, expected);
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## publickey der -> pem', async function (t) {
    try {
      const keys = crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: {
          type: 'spki',
          format: 'der',
        },
        privateKeyEncoding: {
          type: 'pkcs1',
          format: 'der',
        },
      });
      const expected = crypto
        .createPublicKey({
          key: keys.publicKey,
          format: 'der',
          type: 'spki',
        })
        .export({
          type: 'spki',
          format: 'pem',
        }) as string;

      const pem = KeyParser.der2pem('PUBLIC KEY', keys.publicKey);
      t.same(pem.replace(/(\n|\r|\r\n)+/g, ''), expected.replace(/(\n|\r|\r\n)+/g, ''));
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## privatekey der -> pem', async function (t) {
    try {
      const keys = crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: {
          type: 'spki',
          format: 'der',
        },
        privateKeyEncoding: {
          type: 'pkcs1',
          format: 'der',
        },
      });
      const expected = crypto
        .createPrivateKey({
          key: keys.privateKey,
          format: 'der',
          type: 'pkcs1',
        })
        .export({
          type: 'pkcs1',
          format: 'pem',
        }) as string;

      const pem = KeyParser.der2pem('PRIVATE KEY', keys.privateKey);
      t.same(pem.replace(/(\n|\r|\r\n)+/g, ''), expected.replace(/(\n|\r|\r\n)+/g, '').replace(/(RSA )/g, ''));
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
