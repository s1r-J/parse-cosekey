import { test } from 'tap';
import {
  COSEKeyCommonParameter,
  COSEKeyType,
  COSEKeyTypeParameter,
  COSEKeyOperationValue,
  COSEEllipticCurve,
  COSEAlgorithm,
  COSEKeyParameterValueMapping,
} from '../dist/coseKey';
import KeyParseError from '../dist/exception/keyParseError';

test('# coseKey', function (t) {
  t.test('## COSEKeyType', function (t) {
    t.test('### name', function (t) {
      const found = COSEKeyType.WALNUT_DSA.name;
      t.same(found, 'WalnutDSA');
      t.end();
    });

    t.test('### value', function (t) {
      const found = COSEKeyType.HSS_LMS.value;
      t.same(found, 5);
      t.end();
    });

    t.test('### description', function (t) {
      const found = COSEKeyType.SYMMETRIC.description;
      t.same(found, 'Symmetric Keys');
      t.end();
    });

    t.test('### values', function (t) {
      const found = COSEKeyType.values();
      t.same(found.length, 6);
      t.end();
    });

    t.test('### fromValue', function (t) {
      const found = COSEKeyType.fromValue(1);
      t.same(found, COSEKeyType.OKP);
      t.end();
    });

    t.test('### fromName', function (t) {
      const found = COSEKeyType.fromName('EC2');
      t.same(found, COSEKeyType.EC2);
      t.end();
    });

    t.end();
  });

  t.test('## COSEKeyCommonParameter', function (t) {
    t.test('### name', function (t) {
      const found = COSEKeyCommonParameter.KTY.name;
      t.same(found, 'kty');
      t.end();
    });

    t.test('### label', function (t) {
      const found = COSEKeyCommonParameter.KID.label;
      t.same(found, 2);
      t.end();
    });

    t.test('### description', function (t) {
      const found = COSEKeyCommonParameter.ALG.description;
      t.same(found, 'Key usage restriction to this algorithm');
      t.end();
    });

    t.test('### values', function (t) {
      const found = COSEKeyCommonParameter.values();
      t.same(found.length, 5);
      t.end();
    });

    t.test('### fromName', function (t) {
      const found = COSEKeyCommonParameter.fromName('key_ops');
      t.same(found, COSEKeyCommonParameter.KEY_OPS);
      t.end();
    });

    t.test('### fromLabel', function (t) {
      const found = COSEKeyCommonParameter.fromLabel(5);
      t.same(found, COSEKeyCommonParameter.BASE_IV);
      t.end();
    });

    t.end();
  });

  t.test('## COSEKeyTypeParameter', function (t) {
    t.test('### keyType', function (t) {
      const found = COSEKeyTypeParameter.OKP_CRV.keyType;
      t.same(found, COSEKeyType.OKP);
      t.end();
    });

    t.test('### name', function (t) {
      const found = COSEKeyTypeParameter.EC2_CRV.name;
      t.same(found, 'crv');
      t.end();
    });

    t.test('### label', function (t) {
      const found = COSEKeyTypeParameter.RSA_N.label;
      t.same(found, -1);
      t.end();
    });

    t.test('### description', function (t) {
      const found = COSEKeyTypeParameter.OTHER.description;
      t.same(found, 'other prime infos, an array');
      t.end();
    });

    t.test('### values', function (t) {
      const found = COSEKeyTypeParameter.values();
      t.same(found.length, 27);
      t.end();
    });

    t.test('### fromLabel', function (t) {
      const found = COSEKeyTypeParameter.fromLabel(COSEKeyType.SYMMETRIC, -1);
      t.same(found, COSEKeyTypeParameter.SYMMETRIC_K);
      t.end();
    });

    t.test('### fromName', function (t) {
      const found = COSEKeyTypeParameter.fromName(COSEKeyType.WALNUT_DSA, 'matrix 2');
      t.same(found, COSEKeyTypeParameter.MATRIX_2);
      t.end();
    });

    t.end();
  });

  t.test('## COSEKeyOperationValue', function (t) {
    t.test('### name', function (t) {
      const found = COSEKeyOperationValue.SIGN.name;
      t.same(found, 'sign');
      t.end();
    });

    t.test('### value', function (t) {
      const found = COSEKeyOperationValue.VERIFY.value;
      t.same(found, 2);
      t.end();
    });

    t.test('### description', function (t) {
      const found = COSEKeyOperationValue.ENCRYPT.description;
      t.same(found, 'The key is used for key transport encryption.');
      t.end();
    });

    t.test('### values', function (t) {
      const found = COSEKeyOperationValue.values();
      t.same(found.length, 10);
      t.end();
    });

    t.test('### fromValue', function (t) {
      const found = COSEKeyOperationValue.fromValue(10);
      t.same(found, COSEKeyOperationValue.MAC_VERIFY);
      t.end();
    });

    t.test('### fromName', function (t) {
      const found = COSEKeyOperationValue.fromName('MAC create');
      t.same(found, COSEKeyOperationValue.MAC_CREATE);
      t.end();
    });

    t.end();
  });

  t.test('## COSEEllipticCurve', function (t) {
    t.test('### name', function (t) {
      const found = COSEEllipticCurve.P_256.name;
      t.same(found, 'P-256');
      t.end();
    });

    t.test('### value', function (t) {
      const found = COSEEllipticCurve.P_384.value;
      t.same(found, 2);
      t.end();
    });

    t.test('### keyType', function (t) {
      const found = COSEEllipticCurve.P_512.keyType;
      t.same(found, COSEKeyType.EC2);
      t.end();
    });

    t.test('### description', function (t) {
      const found = COSEEllipticCurve.X25519.description;
      t.same(found, 'X25519 for use w/ ECDH only');
      t.end();
    });

    t.test('### values', function (t) {
      const found = COSEEllipticCurve.values();
      t.same(found.length, 8);
      t.end();
    });

    t.test('### fromValue', function (t) {
      const found = COSEEllipticCurve.fromValue(COSEKeyType.OKP, 5);
      t.same(found, COSEEllipticCurve.X448);
      t.end();
    });

    t.test('### fromName', function (t) {
      const found = COSEEllipticCurve.fromName(COSEKeyType.OKP, 'Ed25519');
      t.same(found, COSEEllipticCurve.ED25519);
      t.end();
    });

    t.end();
  });

  t.test('## COSEAlgorithm', function (t) {
    t.test('### name', function (t) {
      const found = COSEAlgorithm.RS1.name;
      t.same(found, 'RS1');
      t.end();
    });

    t.test('### value', function (t) {
      const found = COSEAlgorithm.WALNUT_DSA.value;
      t.same(found, -260);
      t.end();
    });

    t.test('### description', function (t) {
      const found = COSEAlgorithm.RS512.description;
      t.same(found, 'RSASSA-PKCS1-v1_5 using SHA-512');
      t.end();
    });

    t.test('### nodeCryptoHashAlg', function (t) {
      const found = COSEAlgorithm.RS384.nodeCryptoHashAlg;
      t.same(found, 'sha384');
      t.end();
    });

    t.test('### values', function (t) {
      const found = COSEAlgorithm.values();
      t.same(found.length, 64);
      t.end();
    });

    t.test('### fromValue', function (t) {
      const found = COSEAlgorithm.fromValue(-7);
      t.same(found, COSEAlgorithm.ES256);
      t.end();
    });

    t.test('### fromName', function (t) {
      const found = COSEAlgorithm.fromName('IV-GENERATION');
      t.same(found, COSEAlgorithm.IV_GENERATION);
      t.end();
    });

    t.end();
  });

  t.test('## COSEKeyParameterValueMapping', function (t) {
    t.test('### parameter', function (t) {
      const found = COSEKeyParameterValueMapping.KTY.parameter;
      t.same(found, COSEKeyCommonParameter.KTY);
      t.end();
    });

    t.test('### value', function (t) {
      const found = COSEKeyParameterValueMapping.ALG.value;
      t.same(found, COSEAlgorithm);
      t.end();
    });

    t.test('### values', function (t) {
      const found = COSEKeyParameterValueMapping.values();
      t.same(found.length, 5);
      t.end();
    });

    t.test('### fromParameter', function (t) {
      const found = COSEKeyParameterValueMapping.fromParameter(COSEKeyCommonParameter.KTY);
      t.same(found, COSEKeyParameterValueMapping.KTY);
      t.end();
    });

    t.test('### fromParameterLabel', function (t) {
      const found = COSEKeyParameterValueMapping.KTY.fromParameterLabel(1);
      t.same(found, COSEKeyParameterValueMapping.KTY);
      t.end();
    });

    t.test('### fromValueLabel COSEKeyType', function (t) {
      const found = COSEKeyParameterValueMapping.KTY.fromValueLabel(1);
      t.same(found, COSEKeyType.OKP);
      t.end();
    });

    t.test('### fromValueLabel COSEKeyOperationValue', function (t) {
      const found = COSEKeyParameterValueMapping.KEY_OPS.fromValueLabel(1);
      t.same(found, COSEKeyOperationValue.SIGN);
      t.end();
    });

    t.test('### fromValueLabel COSEEllipticCurve', function (t) {
      const found = COSEKeyParameterValueMapping.EC2_CRV.fromValueLabel(1, COSEKeyType.EC2);
      t.same(found, COSEEllipticCurve.P_256);
      t.end();
    });

    t.test('### fromValueLabel COSEEllipticCurve throw error', function (t) {
      try {
        COSEKeyParameterValueMapping.EC2_CRV.fromValueLabel(1);
        t.fail('Should throw error');
      } catch (err) {
        t.type(err, KeyParseError);
      }
      t.end();
    });

    t.test('### fromValueLabel COSEEllipticCurve not found', function (t) {
      const found = COSEKeyParameterValueMapping.EC2_CRV.fromValueLabel(999999, COSEKeyType.EC2);
      t.same(found, null);
      t.end();
    });

    t.test('### fromValueLabel COSEAlgorithm', function (t) {
      const found = COSEKeyParameterValueMapping.ALG.fromValueLabel(1);
      t.same(found, COSEAlgorithm.A128GCM);
      t.end();
    });

    t.test('### fromValueName COSEKeyType', function (t) {
      const found = COSEKeyParameterValueMapping.KTY.fromValueName('RSA');
      t.same(found, COSEKeyType.RSA);
      t.end();
    });

    t.test('### fromValueName COSEKeyOperationValue', function (t) {
      const found = COSEKeyParameterValueMapping.KEY_OPS.fromValueName('verify');
      t.same(found, COSEKeyOperationValue.VERIFY);
      t.end();
    });

    t.test('### fromValueName COSEEllipticCurve', function (t) {
      const found = COSEKeyParameterValueMapping.OKP_CRV.fromValueName('Ed25519', COSEKeyType.OKP);
      t.same(found, COSEEllipticCurve.ED25519);
      t.end();
    });

    t.test('### fromValueName COSEEllipticCurve throw error', function (t) {
      try {
        COSEKeyParameterValueMapping.OKP_CRV.fromValueLabel('Ed25519');
        t.fail('Should throw error');
      } catch (err) {
        t.type(err, KeyParseError);
      }
      t.end();
    });

    t.test('### fromValueName COSEAlgorithm', function (t) {
      const found = COSEKeyParameterValueMapping.ALG.fromValueName('ES256K');
      t.same(found, COSEAlgorithm.ES256K);
      t.end();
    });

    t.end();
  });

  t.end();
});
