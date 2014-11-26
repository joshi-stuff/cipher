// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.test.test.asymmetric_block_cipher_tests;

import "package:cipher/cipher.dart";
import "package:unittest/unittest.dart";

import "./src/helpers.dart";

void runAsymmetricBlockCipherTests(String algorithmName, Map<Param, dynamic> pubParams, Map<Param,
    dynamic> privParams, List<String> plainCipherTextTuples) {

  group("${algorithmName}:", () {

    group("encrypt:", () {
      final pubCipher = new AsymmetricBlockCipher(algorithmName, {}
          ..[Param.ForEncryption] = true
          ..addAll(pubParams));
      final privCipher = new AsymmetricBlockCipher(algorithmName, {}
          ..[Param.ForEncryption] = true
          ..addAll(privParams));

      for (var i = 0; i < plainCipherTextTuples.length; i += 3) {
        var plainText = plainCipherTextTuples[i];
        var publicCipherText = plainCipherTextTuples[i + 1];
        var privateCipherText = plainCipherTextTuples[i + 2];

        test("public: ${formatAsTruncated(plainText)}", () {
          _runCipherTest(pubCipher, plainText, publicCipherText);
        });

        test("private: ${formatAsTruncated(plainText)}", () {
          _runCipherTest(privCipher, plainText, privateCipherText);
        });

      }
    });

    group("decrypt:", () {
      final pubCipher = new AsymmetricBlockCipher(algorithmName, {}
          ..[Param.ForEncryption] = false
          ..addAll(pubParams));
      final privCipher = new AsymmetricBlockCipher(algorithmName, {}
          ..[Param.ForEncryption] = false
          ..addAll(privParams));

      for (var i = 0; i < plainCipherTextTuples.length; i += 3) {
        var plainText = plainCipherTextTuples[i];
        var publicCipherText = plainCipherTextTuples[i + 1];
        var privateCipherText = plainCipherTextTuples[i + 2];

        test("public: ${formatAsTruncated(plainText)}", () {
          _runDecipherTest(pubCipher, privateCipherText, plainText);
        });

        test("private: ${formatAsTruncated(plainText)}", () {
          _runDecipherTest(privCipher, publicCipherText, plainText);
        });

      }
    });

  });

}

void _runCipherTest(AsymmetricBlockCipher cipher, String plainTextString,
    String expectedHexCipherText) {

  cipher.reset();

  var plainText = createUint8ListFromString(plainTextString);
  var out = cipher.process(plainText);
  var hexOut = formatBytesAsHexString(out);

  expect(hexOut, equals(expectedHexCipherText));
}

void _runDecipherTest(AsymmetricBlockCipher cipher, String hexCipherText,
    String expectedPlainTextString) {

  cipher.reset();

  var cipherText = createUint8ListFromHexString(hexCipherText);
  var out = cipher.process(cipherText);
  var plainText = new String.fromCharCodes(out);

  expect(plainText, equals(expectedPlainTextString));
}
