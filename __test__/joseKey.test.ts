import { test } from 'tap';
import {
  JSONWebKeyEllipticCurve,
  JSONWebKeyOperation,
  JSONWebKeyUse,
  JSONWebKeyParameter,
  JSONWebKeyType,
  JSONWebSignatureAndEncryptionAlgorithm,
} from '../dist/joseKey';

test('# JoseKey', function (t) {
  t.test('## JSONWebKeyType', function (t) {
    t.test('### value', function (t) {
      const found = JSONWebKeyType.EC.value;
      t.same(found, 'EC');
      t.end();
    });

    t.test('### description', function (t) {
      const found = JSONWebKeyType.EC.description;
      t.same(found, 'Elliptic Curve');
      t.end();
    });

    t.test('### values', function (t) {
      const found = JSONWebKeyType.values();
      t.same(found.length, 4);
      t.end();
    });

    t.test('### fromValue', function (t) {
      const found = JSONWebKeyType.fromValue('OKP');
      t.same(found, JSONWebKeyType.OKP);
      t.end();
    });

    t.end();
  });

  t.test('## JSONWebSignatureAndEncryptionAlgorithm', function (t) {
    t.test('### name', function (t) {
      const found = JSONWebSignatureAndEncryptionAlgorithm.HS256.name;
      t.same(found, 'HS256');
      t.end();
    });

    t.test('### description', function (t) {
      const found = JSONWebSignatureAndEncryptionAlgorithm.RS256.description;
      t.same(found, 'RSASSA-PKCS1-v1_5 using SHA-256');
      t.end();
    });

    t.test('### nodeCryptoHashAlg', function (t) {
      const found = JSONWebSignatureAndEncryptionAlgorithm.ES512.nodeCryptoHashAlg;
      t.same(found, 'sha512');
      t.end();
    });

    t.test('### values', function (t) {
      const found = JSONWebSignatureAndEncryptionAlgorithm.values();
      t.same(found.length, 48);
      t.end();
    });

    t.test('### fromName', function (t) {
      const found = JSONWebSignatureAndEncryptionAlgorithm.fromName('PS512');
      t.same(found, JSONWebSignatureAndEncryptionAlgorithm.PS512);
      t.end();
    });

    t.end();
  });

  t.test('## JSONWebKeyEllipticCurve', function (t) {
    t.test('### name', function (t) {
      const found = JSONWebKeyEllipticCurve.P_256.name;
      t.same(found, 'P-256');
      t.end();
    });

    t.test('### description', function (t) {
      const found = JSONWebKeyEllipticCurve.ED448.description;
      t.same(found, 'Ed448 signature algorithm key pairs');
      t.end();
    });

    t.test('### values', function (t) {
      const found = JSONWebKeyEllipticCurve.values();
      t.same(found.length, 8);
      t.end();
    });

    t.test('### fromName', function (t) {
      const found = JSONWebKeyEllipticCurve.fromName('secp256k1');
      t.same(found, JSONWebKeyEllipticCurve.SECP256K1);
      t.end();
    });

    t.end();
  });

  t.test('## JSONWebKeyParameter', function (t) {
    t.test('### name', function (t) {
      const found = JSONWebKeyParameter.X5C.name;
      t.same(found, 'x5c');
      t.end();
    });

    t.test('### description', function (t) {
      const found = JSONWebKeyParameter.EC_X.description;
      t.same(found, 'X Coordinate');
      t.end();
    });

    t.test('### values', function (t) {
      const found = JSONWebKeyParameter.values();
      t.same(found.length, 27);
      t.end();
    });

    t.test('### fromName', function (t) {
      const found = JSONWebKeyParameter.fromName(JSONWebKeyType.OKP, 'x');
      t.same(found, JSONWebKeyParameter.OKP_X);
      t.end();
    });

    t.end();
  });

  t.test('## JSONWebKeyUse', function (t) {
    t.test('### value', function (t) {
      const found = JSONWebKeyUse.SIG.value;
      t.same(found, 'sig');
      t.end();
    });

    t.test('### description', function (t) {
      const found = JSONWebKeyUse.ENC.description;
      t.same(found, 'Encryption');
      t.end();
    });

    t.test('### values', function (t) {
      const found = JSONWebKeyUse.values();
      t.same(found.length, 2);
      t.end();
    });

    t.test('### fromValue', function (t) {
      const found = JSONWebKeyUse.fromValue('enc');
      t.same(found, JSONWebKeyUse.ENC);
      t.end();
    });

    t.end();
  });

  t.test('## JSONWebKeyOperation', function (t) {
    t.test('### value', function (t) {
      const found = JSONWebKeyOperation.SIGN.value;
      t.same(found, 'sign');
      t.end();
    });

    t.test('### description', function (t) {
      const found = JSONWebKeyOperation.VERIFY.description;
      t.same(found, 'Verify digital signature or MAC');
      t.end();
    });

    t.test('### values', function (t) {
      const found = JSONWebKeyOperation.values();
      t.same(found.length, 8);
      t.end();
    });

    t.test('### fromValue', function (t) {
      const found = JSONWebKeyOperation.fromValue('deriveBits');
      t.same(found, JSONWebKeyOperation.DERIVE_BITS);
      t.end();
    });

    t.end();
  });

  t.end();
});
