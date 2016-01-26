// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

/**
 * This library contains all out-of-the-box implementations of the interfaces provided in the API
 * which are compatible with client and server sides.
 *
 * You can extend it with client side algorithms by including library [cipher.impl_client] in
 * addition to this one. You can also extend is with its server side counterpart by including
 * library [cipher.impl_server] in addition to this one
 *
 * You must call [initCipher] method before using this library to load all implementations into
 * cipher's API factories.
 */
library cipher.impl;

import "dart:mirrors";

import "package:bignum/bignum.dart";

import "package:cipher/adapters/stream_cipher_as_block_cipher.dart";

import "package:cipher/api.dart";

export "package:cipher/asymmetric/api.dart";
import "package:cipher/asymmetric/rsa.dart";
import "package:cipher/asymmetric/pkcs1.dart";

import "package:cipher/block/aes_fast.dart";

import "package:cipher/digests/md2.dart";
import "package:cipher/digests/md4.dart";
import "package:cipher/digests/md5.dart";
import "package:cipher/digests/ripemd128.dart";
import "package:cipher/digests/ripemd160.dart";
import "package:cipher/digests/ripemd256.dart";
import "package:cipher/digests/ripemd320.dart";
import "package:cipher/digests/sha1.dart";
import "package:cipher/digests/sha224.dart";
import "package:cipher/digests/sha256.dart";
import "package:cipher/digests/sha3.dart";
import "package:cipher/digests/sha384.dart";
import "package:cipher/digests/sha512.dart";
import "package:cipher/digests/sha512t.dart";
import "package:cipher/digests/tiger.dart";
import "package:cipher/digests/whirlpool.dart";

export "package:cipher/ecc/api.dart";
import "package:cipher/ecc/api.dart";
import "package:cipher/ecc/ecc_base.dart";
import "package:cipher/ecc/ecc_fp.dart" as fp;

export "package:cipher/key_derivators/api.dart";
import "package:cipher/key_derivators/pbkdf2.dart";
import "package:cipher/key_derivators/scrypt.dart";

export "package:cipher/key_generators/api.dart";
import "package:cipher/key_generators/ec_key_generator.dart";
import "package:cipher/key_generators/rsa_key_generator.dart";

import "package:cipher/macs/hmac.dart";

import "package:cipher/modes/cbc.dart";
import "package:cipher/modes/cfb.dart";
import "package:cipher/modes/ecb.dart";
import "package:cipher/modes/gctr.dart";
import "package:cipher/modes/ofb.dart";
import "package:cipher/modes/sic.dart";

import "package:cipher/paddings/padded_block_cipher.dart";
import "package:cipher/paddings/pkcs7.dart";

import "package:cipher/random/api.dart";
import "package:cipher/random/auto_seed_block_ctr_random.dart";
import "package:cipher/random/block_ctr_random.dart";
import "package:cipher/random/fortuna_random.dart";

import "package:cipher/signers/ecdsa_signer.dart";
import "package:cipher/signers/rsa_signer.dart";

import "package:cipher/stream/salsa20.dart";

part "./src/impl/ecc_curves.dart";
//part "./src/impl/registration.dart";

bool _initialized = false;

/**
 * This is the initializer method for this library. It must be called prior to use any of the
 * implementations.
 */
void initCipher() {

  if (!_initialized) {
    _initialized = true;

    //_registerAsymmetricBlockCiphers();
    _register(AsymmetricBlockCipher, RSAEngine, _withName('RSA'));
    _register(AsymmetricBlockCipher, PKCS1Encoding, _withNamePrefix('PKCS1/'));

    //_registerBlockCiphers();
    //_registerDigests();
    //_registerEccStandardCurves();
    //_registerKeyDerivators();
    //_registerKeyGenerators();
    //_registerMacs();
    //_registerModesOfOperation();
    //_registerPaddedBlockCiphers();
    //_registerPaddings();

    //_registerSecureRandoms();
    _register(SecureRandom, AutoSeedBlockCtrRandom, _withName(''));

    //_registerSigners();
    //_registerStreamCiphers();
  }
}

typedef bool _NameChecker(String name);

_NameChecker _withName(String fixedName) => (String name) => name == fixedName;
_NameChecker _withNamePrefix(String namePrefix) => (String name) => name.startsWith(namePrefix);
_NameChecker get _withAnyName => (String name) => true;

void _register(Type interface, Type implementation, _NameChecker nameChecker) {
  var classMirror = reflectClass(interface);
  var registry = classMirror.getField(new Symbol('registry')).reflectee as Registry;

  registry.registerDynamicFactory(_typeFactory(implementation, nameChecker));
}

Factory _typeFactory(Type type, _NameChecker nameChecker) =>
    (String name, Map<Param, dynamic> params) {

  if (!nameChecker(name)) {
    return null;
  }

  NamedAlgorithm algorithm = null;

  var classMirror = reflectClass(type);
  var ctorMirror = classMirror.declarations[classMirror.simpleName] as MethodMirror;
  var firstArgumentTypeSymbol = ctorMirror.parameters[0].type.simpleName;

  if (firstArgumentTypeSymbol == #String) {
    algorithm = _createGenericAlgorithm(classMirror, name, params);

  } else if (firstArgumentTypeSymbol == #Map) {
    algorithm = _createConcreteAlgorithm(classMirror, ctorMirror, name, params);

  } else {
    throw new ArgumentError(
        'Invalid parameter type ${firstArgumentTypeSymbol} found in constructor of type ' +
            '${classMirror.simpleName}');
  }

  _validateCreatedAlgorithm(algorithm, name);

  return algorithm;
};

NamedAlgorithm _createGenericAlgorithm(ClassMirror classMirror, String name, Map<Param,
    dynamic> params) =>
    classMirror.newInstance(new Symbol(''), [name, params]).reflectee;

NamedAlgorithm _createConcreteAlgorithm(ClassMirror classMirror, MethodMirror ctorMirror,
    String name, Map<Param, dynamic> params) {

  var splitName = name.split("/");
  var splitParams = Param.split(params, splitName.length);

  var argumentTypeMirrors = ctorMirror.parameters;
  var argumentValues = [splitParams[0]];

  switch (argumentTypeMirrors.length) {
    case 1:
      break;

    case 2:
      var nextType = argumentTypeMirrors[1].type.reflectedType;
      var nextTypeFactory = _typeFactory(nextType, _withAnyName);

      var nextName = splitName.sublist(1).join('/');
      var nextParams = Param.join(splitParams.sublist(1));

      argumentValues.add(nextTypeFactory(nextName, nextParams));
      break;

    default:
      if (splitName.length != 2) {
        throw new ArgumentError(
            'Invalid algorithm names list ${splitName[1]} found in the middle of algorithm name ' +
                '${name}: algorithm names list can only appear at the end of the algorithm name');
      }

      var nextNames = splitName[1].split(':');
      var expectedParamsCount = argumentTypeMirrors.length - 1;

      if (nextNames.length > expectedParamsCount) {
        throw new ArgumentError(
            'Invalid number of algorithm names found in ${splitName[1]}: expected ' +
                '${expectedParamsCount} arguments');
      }

      var nextParams = Param.split(splitParams[1], expectedParamsCount);

      for (var i = 0; i < expectedParamsCount; i++) {
        var nextType = argumentTypeMirrors[1 + i].type.reflectedType;
        var nextTypeFactory = _typeFactory(nextType, _withAnyName);

        var nextName = (i < nextNames.length) ? nextNames[i] : '';

        argumentValues.add(nextTypeFactory(nextName, nextParams[i]));
      }
      break;
  }

  return classMirror.newInstance(new Symbol(''), argumentValues).reflectee;
}

void _validateCreatedAlgorithm(NamedAlgorithm algorithm, String givenName) {
  var algorithmName = algorithm.algorithmName;
  var name = givenName;

  while (algorithmName.endsWith(':')) {
    algorithmName = algorithmName.substring(0, algorithmName.length - 1);
  }

  while (name.endsWith(':')) {
    name = name.substring(0, name.length - 1);
  }

  if (algorithmName != name) {
    throw new ArgumentError(
        'Given name (${givenName}) and constructed algorithm name (${algorithm.algorithmName}) ' +
            'do not match');
  }
}
