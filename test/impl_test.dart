// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.test.impl_test;

import "package:cipher/cipher.dart";

import "package:unittest/unittest.dart";

import './test/registry_tests.dart';

class Algol implements Algorithm {

  final String _name;
  final Map<Param, dynamic> _params;
  final Algol _chainedAlgorithm;

  Algol(this._name, this._params, this._chainedAlgorithm);

  String toString() {
    StringBuffer sb = new StringBuffer();

    sb.write(_name);
    sb.write(": ");
    sb.write(_params);
    sb.write("\n");

    if (_chainedAlgorithm != null) {
      sb.write(_chainedAlgorithm.toString());
    }

    return sb.toString();
  }
}

void main() {
  var registry = new Registry<Algorithm>();

  registry.registerDynamicFactory(
      new ConcreteAlgorithmFactory(
          "A",
          (params, chainedAlgorithm) => new Algol("A", params, chainedAlgorithm),
          new ConcreteAlgorithmFactory(
              "B",
              (params, chainedAlgorithm) => new Algol("B", params, chainedAlgorithm),
              new ConcreteAlgorithmFactory(
                  "C",
                  (params, chainedAlgorithm) => new Algol("C", params, chainedAlgorithm),
                  new ConcreteAlgorithmFactory(
                      "D",
                      (params, chainedAlgorithm) => new Algol("D", params, chainedAlgorithm))))));

  var params = {
    Param.Key: [1, 2, 3],
    Param.Chain: [{
        Param.BitStrength: 7
      }, {
        Param.BlockSize: 8
      }, {
        Param.ForEncryption: true,
        Param.IV: [1, 2]
      }, {
        Param.Salt: [1, 2, 3, 4, 5]
      }]
  };

  var algorithm = registry.create("A/B/C/D", params);

  print(algorithm);

//  var algorithm2 = registry.create("B/C/D", params);

//  print(algorithm2);
}

typedef Algorithm NamedCreator(String name, Map<Param, dynamic> params, Algorithm chainedAlgorithm);
typedef Algorithm UnnamedCreator(Map<Param, dynamic> params, Algorithm chainedAlgorithm);

abstract class Factory {

  Factory _nextFactory;

  Factory([this._nextFactory]);

  Algorithm call(String name, Map<Param, dynamic> params, [Algorithm chainedAlgorithm]) {
    var names = name.split("/");

    var unchainedParams = Param.split(params, names.length);

    Algorithm algorithm = _create(names.first, unchainedParams.first, chainedAlgorithm);

    if (_nextFactory == null) {
      return algorithm;
    } else {
      return _nextFactory.call(
          names.sublist(1).join("/"),
          Param.merge(unchainedParams.sublist(1)),
          algorithm);
    }
  }

  Algorithm _create(String name, Map<Param, dynamic> params, Algorithm chainedAlgorithm);

}

class ConcreteAlgorithmFactory extends Factory {

  final String _algorithmName;
  final UnnamedCreator _unnamedCreator;

  ConcreteAlgorithmFactory(this._algorithmName, this._unnamedCreator, [Factory nextFactory])
      : super(nextFactory);

  Algorithm _create(String name, Map<Param, dynamic> params, Algorithm chainedAlgorithm) {
    if (name != _algorithmName) return null;

    return _unnamedCreator(params, chainedAlgorithm);
  }

}











/*

class MultiplexFactory extends Factory {

  final Map<int, NamedCreator> _namedCreators;

  MultiplexFactory(this._namedCreators);

  Algorithm _create(String name, Map<Param, dynamic> params, Algorithm chainedAlgorithm) {
    var names = name.split("/");
    var namedCreator = _namedCreators[names.length];

    if (namedCreator != null) {
      return namedCreator(name, params, chainedAlgorithm);
    }

    return null;
  }

}

class SecureRandomFactory extends GenericAlgorithmFactory {

  SecureRandomFactory() : super((name, params, chainedAlgorithm) => new SecureRandom(name, params));

}

class GenericAlgorithmFactory extends Factory {

  final NamedCreator _namedCreator;

  GenericAlgorithmFactory(this._namedCreator);

  Algorithm _create(String name, Map<Param, dynamic> params, Algorithm chainedAlgorithm) {
    var names = name.split("/");

    var unchainedParams = Param.split(params, names.length);

    return _namedCreator(name, unchainedParams.last, chainedAlgorithm);
  }

}
*/

/*
void main() {

  initCipher();

  group("impl:", () {

    test("initCipher() can be called several times", () {
      initCipher();
      initCipher();
    });

    test("AsymmetricBlockCipher returns valid implementations", () {
      testAsymmetricBlockCipher("RSA");
      testAsymmetricBlockCipher("RSA/PKCS1");
    });

    test("BlockCipher returns valid implementations", () {
      testBlockCipher("AES");
    });

    test("Digest returns valid implementations", () {
      testDigest("MD2");
      testDigest("MD4");
      testDigest("MD5");
      testDigest("RIPEMD-128");
      testDigest("RIPEMD-160");
      testDigest("RIPEMD-256");
      testDigest("RIPEMD-320");
      testDigest("SHA-1");
      testDigest("SHA-224");
      testDigest("SHA-256");
      testDigest("SHA-3/512");
      testDigest("SHA-384");
      testDigest("SHA-512");
      testDigest("SHA-512/448");
      testDigest("Tiger");
      testDigest("Whirlpool");
    });

    test("ECDomainParameters returns valid implementations", () {
      testECDomainParameters("prime192v1");
    });

    test("KeyDerivator returns valid implementations", () {
      testKeyDerivator("SHA-1/HMAC/PBKDF2");
      testKeyDerivator("scrypt");
    });

    test("KeyGenerator returns valid implementations", () {
      testKeyGenerator("EC");
      testKeyGenerator("RSA");
    });

    test("Mac returns valid implementations", () {
      testMac("SHA-1/HMAC");
      testMac("SHA-256/HMAC");
      testMac("RIPEMD-160/HMAC");
    });

    test("BlockCipher returns valid implementations for modes of operation", () {
      testBlockCipher("AES/CBC");
      testBlockCipher("AES/CFB-64");
      testBlockCipher("AES/CTR");
      testBlockCipher("AES/ECB");
      testBlockCipher("AES/OFB-64/GCTR");
      testBlockCipher("AES/OFB-64");
      testBlockCipher("AES/SIC");
    });

    test("PaddedBlockCipher returns valid implementations", () {
      testPaddedBlockCipher("AES/SIC/PKCS7");
    });

    test("Padding returns valid implementations", () {
      testPadding("PKCS7");
    });

    test("SecureRandom returns valid implementations", () {
      testSecureRandom("AES/CTR/AUTO-SEED-PRNG");
      testSecureRandom("AES/CTR/PRNG");
      testSecureRandom("Fortuna");
    });

    test("Signer returns valid implementations", () {
      testSigner("SHA-1/ECDSA");
      testSigner("MD2/RSA");
      testSigner("MD4/RSA");
      testSigner("MD5/RSA");
      testSigner("RIPEMD-128/RSA");
      testSigner("RIPEMD-160/RSA");
      testSigner("RIPEMD-256/RSA");
      testSigner("SHA-1/RSA");
      testSigner("SHA-224/RSA");
      testSigner("SHA-256/RSA");
      testSigner("SHA-384/RSA");
      testSigner("SHA-512/RSA");
    });

    test("StreamCipher returns valid implementations", () {
      testStreamCipher("Salsa20");
      testStreamCipher("AES/SIC");
      testStreamCipher("AES/CTR");
    });

  });

}
*/
