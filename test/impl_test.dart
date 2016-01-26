// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.test.impl_test;

import "package:cipher/cipher.dart";

import "package:unittest/unittest.dart";

import './test/registry_tests.dart';

/*
 * StreamCipherAsBlockCipher -> BlockCipher("SALSA20") ?no se si publicarlo
 * PKCS1Encoding -> AsymmetricBlockCipher("PKCS1/RSA")
 *                  AsymmetricBlockCipher("PKCS1/RSA:HW_SECRND")
 * RSAEngine -> AsymmetricBlockCipher("RSA")
 * AESFastEngine -> BlockCipher("AES")
 * MD2Digest -> Digest("MD2")
 *    MD4, MD5,
 *    RIPEMD-128, RIPEMD-160, RIPEMD-256, RIPEMD-320,
 *    SHA-1, SHA-224, SHA-256, SHA-384, SHA-512,
 *    SHA-3-224, SHA-3-256, SHA-3-288, SHA-3-384, SHA-3-512,
 *    SHA-512t-8, SHA-512t-16, ..., SHA-512t-512
 * TigerDigest -> Digest("Tiger")
 * WhirlpoolDigest -> Digest("Whirlpool")
 * PBKDF2KeyDerivator -> KeyDerivator("PBKDF2/HMAC/MD2")
 * Scrypt -> KeyDerivator("scrypt")
 * ECKeyGenerator -> KeyGenerator("EC/HW_SECRND")
 * RSAKeyGenerator -> KeyGenerator("RSA/HW_SECRND")
 * HMac -> Mac("HMAC/MD2") (esta acoplado con el digest por el tamaño del blockSize)
 * CBCBlockCipher -> BlockCipher("CBC/AES")
 * CFBBlockCipher -> BlockCipher("CFB-{bitBlockSize}/AES") (no parece haber restriccion en el valor de bitBlockSize)
 * ECBBlockCipher -> BlockCipher("ECB/AES")
 * GCTRBlockCipher -> BlockCipher("GCTR/AES")
 * OFBBlockCipher -> BlockCipher("OFB-{bitBlockSize}/AES") (no parece haber restriccion en el valor de bitBlockSize)
 * SICStreamCipher -> StreamCipher("SIC/AES")
 * PaddedBlockCipherImpl -> PaddedBlockCipher("PKCS7/AES")
 * PKCS7Padding -> Padding("PKCS7")
 * AutoSeedBlockCtrRandom -> SecureRandom("AUTO-SEED-PRNG/AES")
 *                           SecureRandom("AUTO-SEED-IV-PRNG/AES")
 * BlockCtrRandom -> SecureRandom("PRNG/AES")
 * FortunaRandom -> SecureRandom("Fortuna")
 * ECDSASigner -> Signer("ECDSA/MD2:HW_SECRND")
 *                Signer("DET-ECDSA/MD2") (este crearia el HMAC dentro)
 * RSASigner -> Signer("RSA/MD2") (esta acoplado con el digest por el identificador DER del digest)
 * Salsa20Engine -> StreamCipher("Salsa20")
 *
 * se crean de dcha a izda:
 * ECDSA, PKCS1 signer necesita 2 algoritmos:
 * se usa / para pasar al constructor
 * se usa : para separar multiples parametros para el siguiente constructor (solo puede ser terminal)
 * se usa - para distinguir subalgoritmos (ej: ECDSA, DET-ECDSA)
 */

/*
class Algol implements NamedAlgorithm {

  final String algorithmName;
  final Map<Param, dynamic> _params;
  final List<Algol> _nextAlgorithms;

  Algol(this.algorithmName, this._params, [this._nextAlgorithms]);

  String toString([int indent = 0]) {
    StringBuffer sb = new StringBuffer();

    String tabs = new String.fromCharCodes(new List<int>.filled(indent, 32));

    sb.write(tabs + algorithmName);
    sb.write(" ");
    sb.write(_params.toString());

    if (_nextAlgorithms != null) {
      sb.write(" {{\n");
      for (var algorithm in _nextAlgorithms) {
        sb.write(algorithm.toString(indent + 2));
      }
      sb.write(tabs + "}}\n");
    } else {
      sb.write("\n");
    }

    return sb.toString();
  }

}

////////////////////////////////////////////////////////////////////////////////////////////////////

abstract class Mode implements NamedAlgorithm {
  static final registry = new Registry<Mode>();

  factory Mode(String name, Map params) => registry.create(name, params);
}

abstract class Cipher implements NamedAlgorithm {
  static final registry = new Registry<Cipher>();

  factory Cipher(String name, Map params) => registry.create(name, params);
}

abstract class Digest implements NamedAlgorithm {
  static final registry = new Registry<Digest>();

  factory Digest(String name, Map params) => registry.create(name, params);
}

abstract class Random implements NamedAlgorithm {
  static final registry = new Registry<Random>();

  factory Random(String name, Map params) => registry.create(name, params);
}

////////////////////////////////////////////////////////////////////////////////////////////////////

class CBC extends Algol implements Mode {
  CBC(Map<Param, dynamic> params, Cipher cipher)
      : super("CBC/${cipher.algorithmName}", params, [cipher]);
}

class AES extends Algol implements Cipher {
  AES(Map<Param, dynamic> params, Digest digest, Random random)
      : super("AES/${digest.algorithmName}:${random.algorithmName}", params, [digest, random]);
}

class DES extends Algol implements Cipher {
  DES(Map<Param, dynamic> params) : super("DES", params);
}

class MD2 extends Algol implements Digest {
  MD2(Map<Param, dynamic> params) : super("MD2", params);
}

class MD3 extends Algol implements Digest {
  MD3(Map<Param, dynamic> params) : super("MD3", params);
}

class HardwareRandom extends Algol implements Random {
  HardwareRandom(Map params) : super("HW_RND", params);
}

class DefaultRandom extends Algol implements Random {
  DefaultRandom(Map params) : super("", params);
}

////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////

void main() {

  bind(Digest, MD2, withName('MD2'));
  bind(Digest, MD3, withName('MD3'));
  bind(Random, HardwareRandom, withName('HW_RND'));
  bind(Random, DefaultRandom, withName(''));
  bind(Cipher, DES, withName('DES'));
  bind(Cipher, AES, withNamePrefix('AES/'));
  bind(Mode, CBC, withNamePrefix('CBC/'));

  var params = {
    Param.Key: [1, 2, 3],
    Param.Chain: [{
        Param.IV: [1, 2]
      }, {
        Param.ForEncryption: true
      }, {
        Param.DesiredKeyLength: 7,
        Param.Chain: [{
            Param.BlockSize: 8,
          }, {
            Param.BitStrength: 7,
            Param.Salt: [1, 2, 3, 4, 5]
          }]
      }]
  };

  print(new Digest("MD2", params));
  print(new Digest("MD3", params));
  print(new Random("HW_RND", params));
  print(new Cipher("DES", params));
  print(new Mode("CBC/DES", params));
  print(new Mode("CBC/AES/MD2:HW_RND", params));
  print(new Mode("CBC/AES/MD2:", params));
  print(new Mode("CBC/AES/MD2", params));
}
*/


void main() {

  initCipher();

  group("impl:", () {

    test("initCipher() can be called several times", () {
      initCipher();
      initCipher();
    });

    test("AsymmetricBlockCipher returns valid implementations", () {
      testAsymmetricBlockCipher("RSA");
      testAsymmetricBlockCipher("PKCS1/RSA");
    });
/*
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
    */
  });

}
