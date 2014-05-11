// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.test.padded_block_cipher_test;

import "package:cipher/cipher.dart";
import "package:cipher/impl/base.dart";
import "package:unittest/unittest.dart";

import "../test/src/null_block_cipher.dart";
import "../test/src/helpers.dart";

void main() {

  initCipher();
  BlockCipher.registry["Null"] = (_) => new NullBlockCipher();

  group( "PaddedBlockCipherTest works", () {

    test( "cipher", () {

      var params = new PaddedBlockCipherParameters( null, null );
      var pbc = new PaddedBlockCipher("Null/PKCS7");

      pbc.init( true, params );

      var inp = createUint8ListFromSequentialNumbers(3*pbc.blockSize~/2);
      var out = pbc.process(inp);

      expect( formatBytesAsHexString(out), "000102030405060708090a0b0c0d0e0f10111213141516170808080808080808" );

    });

  });

}

