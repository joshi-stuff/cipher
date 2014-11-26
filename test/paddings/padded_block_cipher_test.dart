// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.test.padded_block_cipher_test;

import "package:cipher/cipher.dart";

import "package:unittest/unittest.dart";

import "../test/src/null_block_cipher.dart";
import "../test/src/helpers.dart";

void main() {
  initCipher();
  BlockCipher.registry["Null"] = (name, params) => new NullBlockCipher(Param.split(params, 1)[0]);

  var cipher = new PaddedBlockCipher("Null/PKCS7", {
    Param.Chain: [{
        Param.ForEncryption: true,
      }, {
        Param.ForPadding: true,
        Param.BlockSize: 16
      }]
  });
  var decipher = new PaddedBlockCipher("Null/PKCS7", {
    Param.Chain: [{
        Param.ForEncryption: false,
      }, {
        Param.ForPadding: false,
      }]
  });

  group("PaddedBlockCipher:", () {

    group("partial blocks:", () {
      var sequence = createUint8ListFromSequentialNumbers(24);
      var paddedSequenceHex = "000102030405060708090a0b0c0d0e0f10111213141516170808080808080808";

      test("cipher", () {
        cipher.reset();

        var out = cipher.process(sequence);

        expect(formatBytesAsHexString(out), paddedSequenceHex);
      });

      test("decipher", () {
        decipher.reset();

        var out = decipher.process(createUint8ListFromHexString(paddedSequenceHex));

        expect(formatBytesAsHexString(out), formatBytesAsHexString(sequence));
      });
    });

    group("whole blocks:", () {
      var sequence = createUint8ListFromSequentialNumbers(16);
      var paddedSequenceHex = "000102030405060708090a0b0c0d0e0f10101010101010101010101010101010";

      test("cipher", () {
        cipher.reset();

        var out = cipher.process(sequence);

        expect(formatBytesAsHexString(out), paddedSequenceHex);
      });

      test("decipher", () {
        decipher.reset();

        var out = decipher.process(createUint8ListFromHexString(paddedSequenceHex));

        expect(formatBytesAsHexString(out), formatBytesAsHexString(sequence));
      });
    });
  });
}
