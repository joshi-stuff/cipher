// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.modes.gctr;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/block/base_block_cipher.dart";
import "package:cipher/src/ufixnum.dart";

/// Implementation of GOST 28147 OFB counter mode (GCTR) on top of a [BlockCipher].
class GCTRBlockCipher extends BaseBlockCipher {

  static const C1 = 16843012; //00000001000000010000000100000100
  static const C2 = 16843009; //00000001000000010000000100000001

  final BlockCipher _cipher;

  final Uint8List _IV;

  bool _firstStep = true;
  int _N3;
  int _N4;
  Uint8List _ofbV;
  Uint8List _ofbOutV;

  GCTRBlockCipher(Map<Param, dynamic> params, BlockCipher cipher)
      : super("${cipher.algorithmName}/GCTR", params),
        _cipher = cipher,
        _IV = new Uint8List(cipher.blockSize) {

    if (blockSize != 8) {
      throw new ArgumentError("GCTR can only be used with 64 bit block ciphers");
    }

    _initIV(params);

    _ofbV = new Uint8List(_cipher.blockSize);
    _ofbOutV = new Uint8List(_cipher.blockSize);

    reset();
  }

  int get blockSize => _cipher.blockSize;

  void reset() {
    _cipher.reset();

    _firstStep = true;
    _N3 = 0;
    _N4 = 0;
    _ofbV.setRange(0, _IV.length, _IV);
    _ofbOutV.fillRange(0, _ofbOutV.length, 0);
  }

  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    if ((inpOff + blockSize) > inp.length) {
      throw new ArgumentError("Input buffer too short");
    }

    if ((outOff + blockSize) > out.length) {
      throw new ArgumentError("Output buffer too short");
    }

    if (_firstStep) {
      _firstStep = false;
      _cipher.processBlock(_ofbV, 0, _ofbOutV, 0);
      _N3 = _bytesToint(_ofbOutV, 0);
      _N4 = _bytesToint(_ofbOutV, 4);
    }
    _N3 += C2;
    _N4 += C1;
    _intTobytes(_N3, _ofbV, 0);
    _intTobytes(_N4, _ofbV, 4);

    _cipher.processBlock(_ofbV, 0, _ofbOutV, 0);

    // XOR the ofbV with the plaintext producing the cipher text (and the next input block).
    for (var i = 0; i < blockSize; i++) {
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
      _IV.setRange(offset, _IV.length, iv);
    } else {
      _IV.setRange(0, _IV.length, iv);
    }
  }

  int _bytesToint(Uint8List inp, int inpOff) {
    return unpack32(inp, inpOff, Endianness.LITTLE_ENDIAN);
  }

  void _intTobytes(int num, Uint8List out, int outOff) {
    pack32(num, out, outOff, Endianness.LITTLE_ENDIAN);
  }

}
