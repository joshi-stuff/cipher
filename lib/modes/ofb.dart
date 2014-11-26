// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.modes.ofb;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/block/base_block_cipher.dart";

/// Implementation of Output FeedBack mode (OFB) on top of a [BlockCipher].
class OFBBlockCipher extends BaseBlockCipher {

  final BlockCipher _cipher;
  final int blockSize;

  final Uint8List _IV;

  Uint8List _ofbV;
  Uint8List _ofbOutV;

  OFBBlockCipher(Map<Param, dynamic> params, BlockCipher cipher, int blockSize)
      : super("${cipher.algorithmName}/OFB-${blockSize*8}", params),
        _cipher = cipher,
        blockSize = blockSize,
        _IV = new Uint8List(cipher.blockSize) {

    _initIV(params);

    _ofbV = new Uint8List(_cipher.blockSize);
    _ofbOutV = new Uint8List(_cipher.blockSize);

    reset();
  }

  void reset() {
    _cipher.reset();
    _ofbV.setRange(0, _IV.length, _IV);
  }

  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) {

    if ((inpOff + blockSize) > inp.length) {
      throw new ArgumentError("Input buffer too short");
    }

    if ((outOff + blockSize) > out.length) {
      throw new ArgumentError("Output buffer too short");
    }

    _cipher.processBlock(_ofbV, 0, _ofbOutV, 0);

    // XOR the ofbV with the plaintext producing the cipher text (and the next input block).
    for (int i = 0; i < blockSize; i++) {
      out[outOff + i] = _ofbOutV[i] ^ inp[inpOff + i];
    }

    // change over the input block.
    var offset = _ofbV.length - blockSize;
    _ofbV.setRange(0, offset, _ofbV.sublist(blockSize));
    _ofbV.setRange(offset, _ofbV.length, _ofbOutV);

    return blockSize;
  }

  void _initIV(Map<Param, dynamic> params) {
    var iv = params[Param.IV];

    if (iv == null) {
      iv = new List<int>();
    }

    if (iv.length < _IV.length) {
      // prepend the supplied IV with zeros (per FIPS PUB 81)
      var offset = _IV.length - iv.length;
      _IV.fillRange(0, offset, 0);
      _IV.setAll(offset, iv);

    } else {
      _IV.setRange(0, _IV.length, iv);

    }
  }

}
