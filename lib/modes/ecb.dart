// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.modes.ecb;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/block/base_block_cipher.dart";

/// Implementation of Electronic Code Book (ECB) mode on top of a [BlockCipher].
class ECBBlockCipher extends BaseBlockCipher {

  final BlockCipher _cipher;

  ECBBlockCipher(Map<Param, dynamic> params, BlockCipher cipher)
      : super("${cipher.algorithmName}/ECB", params),
        _cipher = cipher;

  int get blockSize => _cipher.blockSize;

  void reset() {
    _cipher.reset();
  }

  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) =>
      _cipher.processBlock(inp, inpOff, out, outOff);

}
