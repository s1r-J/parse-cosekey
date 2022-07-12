import { test } from 'tap';
import {
  KeyTypeMapping,
  KeyAlgorithmMapping,
  KeyParameterMapping,
  KeyOperationMapping,
  EllipticCurveMapping,
} from '../dist/coseJoseMapping';
import {
  COSEKeyCommonParameter,
  COSEKeyType,
  COSEKeyTypeParameter,
  COSEKeyOperationValue,
  COSEEllipticCurve,
  COSEAlgorithm,
  COSEKeyParameterValueMapping,
} from '../dist/coseKey';
import {
  JSONWebKeyEllipticCurve,
  JSONWebKeyOperation,
  JSONWebKeyUse,
  JSONWebKeyParameter,
  JSONWebKeyType,
  JSONWebSignatureAndEncryptionAlgorithm,
} from '../dist/joseKey';

test('# CoseJoseMapping', function (t) {
  t.test('## KeyTypeMapping', function (t) {
    t.test('### fromCOSEKeyType EC2', function (t) {
      const found = KeyTypeMapping.fromCOSEKeyType(COSEKeyType.EC2);
      t.same(found, JSONWebKeyType.EC);
      t.end();
    });

    t.test('### fromCOSEKeyType not found', function (t) {
      const found = KeyTypeMapping.fromCOSEKeyType(COSEKeyType.SYMMETRIC);
      t.same(found, null);
      t.end();
    });

    t.test('### fromCOSEKeyTypeValue OKP', function (t) {
      const found = KeyTypeMapping.fromCOSEKeyTypeValue(1);
      t.same(found, JSONWebKeyType.OKP);
      t.end();
    });

    t.test('### fromCOSEKeyTypeValue not found', function (t) {
      const found = KeyTypeMapping.fromCOSEKeyTypeValue(99999);
      t.same(found, null);
      t.end();
    });

    t.test('### fromJSONWebKeyType RSA', function (t) {
      const found = KeyTypeMapping.fromJSONWebKeyType(JSONWebKeyType.RSA);
      t.same(found, COSEKeyType.RSA);
      t.end();
    });

    t.test('### fromJSONWebKeyType not found', function (t) {
      const found = KeyTypeMapping.fromJSONWebKeyType(JSONWebKeyType.OCT);
      t.same(found, null);
      t.end();
    });

    t.test('### fromJSONWebKeyTypeValue RSA', function (t) {
      const found = KeyTypeMapping.fromJSONWebKeyTypeValue('RSA');
      t.same(found, COSEKeyType.RSA);
      t.end();
    });

    t.test('### fromJSONWebKeyTypeValue not found', function (t) {
      const found = KeyTypeMapping.fromJSONWebKeyTypeValue('oct');
      t.same(found, null);
      t.end();
    });

    t.end();
  });

  t.test('## KeyAlgorithmMapping', function (t) {
    t.test('### fromCOSEAlgorithm RS1', function (t) {
      const found = KeyAlgorithmMapping.fromCOSEAlgorithm(COSEAlgorithm.RS1);
      t.same(found, JSONWebSignatureAndEncryptionAlgorithm.RS1);
      t.end();
    });

    t.test('### fromCOSEAlgorithm not found', function (t) {
      const found = KeyAlgorithmMapping.fromCOSEAlgorithm(COSEAlgorithm.RSAES_OAEP_w_RFC8017_DEFAULT_PARAMETERS);
      t.same(found, null);
      t.end();
    });

    t.test('### fromCOSEAlgorithmValue RS512', function (t) {
      const found = KeyAlgorithmMapping.fromCOSEAlgorithmValue(COSEAlgorithm.RS512.value);
      t.same(found, JSONWebSignatureAndEncryptionAlgorithm.RS512);
      t.end();
    });

    t.test('### fromCOSEAlgorithmValue not found', function (t) {
      const found = KeyAlgorithmMapping.fromCOSEAlgorithmValue(
        COSEAlgorithm.RSAES_OAEP_w_RFC8017_DEFAULT_PARAMETERS.value,
      );
      t.same(found, null);
      t.end();
    });

    t.test('### fromJoseAlgorithm RS1', function (t) {
      const found = KeyAlgorithmMapping.fromJoseAlgorithm(JSONWebSignatureAndEncryptionAlgorithm.RS384);
      t.same(found, COSEAlgorithm.RS384);
      t.end();
    });

    t.test('### fromJoseAlgorithm not found', function (t) {
      const found = KeyAlgorithmMapping.fromJoseAlgorithm(JSONWebSignatureAndEncryptionAlgorithm.A128CBC_HS256);
      t.same(found, null);
      t.end();
    });

    t.test('### fromJoseAlgorithmName RS256', function (t) {
      const found = KeyAlgorithmMapping.fromJoseAlgorithmName(JSONWebSignatureAndEncryptionAlgorithm.RS256.name);
      t.same(found, COSEAlgorithm.RS256);
      t.end();
    });

    t.test('### fromJoseAlgorithmName not found', function (t) {
      const found = KeyAlgorithmMapping.fromJoseAlgorithmName(
        JSONWebSignatureAndEncryptionAlgorithm.A128CBC_HS256.name,
      );
      t.same(found, null);
      t.end();
    });

    t.end();
  });

  t.test('## KeyParameterMapping', function (t) {
    t.test('### fromCOSEKeyParameter ALG', function (t) {
      const found = KeyParameterMapping.fromCOSEKeyParameter(COSEKeyCommonParameter.ALG);
      t.same(found, JSONWebKeyParameter.ALG);
      t.end();
    });

    t.test('### fromCOSEKeyParameter not found', function (t) {
      const found = KeyParameterMapping.fromCOSEKeyParameter(COSEKeyCommonParameter.BASE_IV);
      t.same(found, null);
      t.end();
    });

    t.test('### fromCOSEKeyParameterLabel ALG', function (t) {
      const found = KeyParameterMapping.fromCOSEKeyParameterLabel(COSEKeyCommonParameter.ALG.label);
      t.same(found, JSONWebKeyParameter.ALG);
      t.end();
    });

    t.test('### fromCOSEKeyParameterLabel not found', function (t) {
      const found = KeyParameterMapping.fromCOSEKeyParameterLabel(COSEKeyCommonParameter.BASE_IV.label);
      t.same(found, null);
      t.end();
    });

    t.test('### fromJSONWebKeyParameter KTY', function (t) {
      const found = KeyParameterMapping.fromJSONWebKeyParameter(JSONWebKeyParameter.KTY);
      t.same(found, COSEKeyCommonParameter.KTY);
      t.end();
    });

    t.test('### fromJSONWebKeyParameter not found', function (t) {
      const found = KeyParameterMapping.fromJSONWebKeyParameter(JSONWebKeyParameter.K);
      t.same(found, null);
      t.end();
    });

    t.test('### fromJSONWebKeyParameterName KTY', function (t) {
      const found = KeyParameterMapping.fromJSONWebKeyParameterName(JSONWebKeyParameter.KTY.name);
      t.same(found, COSEKeyCommonParameter.KTY);
      t.end();
    });

    t.test('### fromJSONWebKeyParameterName not found', function (t) {
      const found = KeyParameterMapping.fromJSONWebKeyParameterName(JSONWebKeyParameter.K.name);
      t.same(found, null);
      t.end();
    });

    t.end();
  });

  t.test('## KeyOperationMapping', function (t) {
    t.test('### fromCOSEKeyOperation VERIFY', function (t) {
      const found = KeyOperationMapping.fromCOSEKeyOperation(COSEKeyOperationValue.VERIFY);
      t.same(found, JSONWebKeyOperation.VERIFY);
      t.end();
    });

    t.test('### fromCOSEKeyOperation not found', function (t) {
      const found = KeyOperationMapping.fromCOSEKeyOperation(COSEKeyOperationValue.MAC_CREATE);
      t.same(found, null);
      t.end();
    });

    t.test('### fromCOSEKeyOperationValue VERIFY', function (t) {
      const found = KeyOperationMapping.fromCOSEKeyOperationValue(COSEKeyOperationValue.VERIFY.value);
      t.same(found, JSONWebKeyOperation.VERIFY);
      t.end();
    });

    t.test('### fromCOSEKeyOperationValue not found', function (t) {
      const found = KeyOperationMapping.fromCOSEKeyOperationValue(COSEKeyOperationValue.MAC_CREATE.value);
      t.same(found, null);
      t.end();
    });

    t.test('### fromJSONWebKeyOperation VERIFY', function (t) {
      const found = KeyOperationMapping.fromJSONWebKeyOperation(JSONWebKeyOperation.VERIFY);
      t.same(found, COSEKeyOperationValue.VERIFY);
      t.end();
    });

    t.test('### fromCOSEKeyOperation not found', function (t) {
      t.pass('Not exist');
      t.end();
    });

    t.test('### fromJSONWebKeyOperationValue VERIFY', function (t) {
      const found = KeyOperationMapping.fromJSONWebKeyOperationValue(JSONWebKeyOperation.VERIFY.value);
      t.same(found, COSEKeyOperationValue.VERIFY);
      t.end();
    });

    t.test('### fromJSONWebKeyOperation not found', function (t) {
      const found = KeyOperationMapping.fromJSONWebKeyOperationValue('not found');
      t.same(found, null);
      t.end();
    });

    t.end();
  });

  t.test('## EllipticCurveMapping', function (t) {
    t.test('### fromCOSEEllipticCurve P_256', function (t) {
      const found = EllipticCurveMapping.fromCOSEEllipticCurve(COSEEllipticCurve.P_256);
      t.same(found, JSONWebKeyEllipticCurve.P_256);
      t.end();
    });

    t.test('### fromCOSEEllipticCurve not found', function (t) {
      t.pass('Not exist');
      t.end();
    });

    t.test('### fromCOSEEllipticCurveValue P_256', function (t) {
      const found = EllipticCurveMapping.fromCOSEEllipticCurveValue(COSEEllipticCurve.P_256.value);
      t.same(found, JSONWebKeyEllipticCurve.P_256);
      t.end();
    });

    t.test('### fromCOSEEllipticCurveValue not found', function (t) {
      const found = EllipticCurveMapping.fromCOSEEllipticCurveValue(999999);
      t.same(found, null);
      t.end();
    });

    t.test('### fromJSONWebKeyEllipticCurve P_384', function (t) {
      const found = EllipticCurveMapping.fromJSONWebKeyEllipticCurve(JSONWebKeyEllipticCurve.P_384);
      t.same(found, COSEEllipticCurve.P_384);
      t.end();
    });

    t.test('### fromJSONWebKeyEllipticCurve not found', function (t) {
      t.pass('Not exist');
      t.end();
    });

    t.test('### fromJSONWebKeyEllipticCurveName P_384', function (t) {
      const found = EllipticCurveMapping.fromJSONWebKeyEllipticCurveName(JSONWebKeyEllipticCurve.P_384.name);
      t.same(found, COSEEllipticCurve.P_384);
      t.end();
    });

    t.test('### fromJSONWebKeyEllipticCurveName not found', function (t) {
      const found = EllipticCurveMapping.fromJSONWebKeyEllipticCurveName('not found');
      t.same(found, null);
      t.end();
    });

    t.end();
  });

  t.end();
});
