// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.test.block.aes_fast_test;

import "package:cipher/cipher.dart";

import '../test/block_cipher_tests.dart';

void main() {

  initCipher();

  runBlockCipherTests("AES", {
    Param.Key: [
        0x00,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0x99,
        0xAA,
        0xBB,
        0xCC,
        0xDD,
        0xEE,
        0xFF]
  },
      [
          "Lorem ipsum dolor sit amet, consectetur adipiscing elit ........",
          "75020e0812adb36f32b1503e0de7a59691e0db8fd1c9efb920695a626cb633d6db0112c007d19d5ea66fe7ab"
              "36c766232b3bcb98fd35f06d27d5a2d475d92728",
          "En un lugar de La Mancha, de cuyo nombre no quiero acordarme ...",
          "29523a5e73c0ffb7f9aaabc737a09e73219bad5e98768b71e2c985b2d8ce217730b0720e1a215f7843c8c7e0"
              "7d44c91212fb1d5b90a791dd147f3746cbc0e28b",]);

}
