// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.modes.cbc;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/block/base_block_cipher.dart";

/// Implementation of Cipher-Block-Chaining (CBC) mode on top of a [BlockCipher].
class CBCBlockCipher extends BaseBlockCipher {

  final BlockCipher _cipher;

  final bool _forEncryption;
  final List<int> _iv;

  Uint8List _cbcV;
  Uint8List _cbcNextV;

  CBCBlockCipher(Map<Param, dynamic> params, BlockCipher cipher)
      : super("${cipher.algorithmName}/CBC", params),
        _cipher = cipher,
        _forEncryption = params[Param.ForEncryption],
        _iv = params[Param.IV] {

    if (_iv.length != blockSize) {
      throw new ArgumentError(
          "Initialization vector must be the same length as block size (${blockSize})");
    }

    _cbcV = new Uint8List(blockSize);
    _cbcNextV = new Uint8List(blockSize);

    reset();
  }

  int get blockSize => _cipher.blockSize;

  void reset() {
    _cipher.reset();

    _cbcV.setAll(0, _iv);
    _cbcNextV.fillRange(0, _cbcNextV.length, 0);
  }

  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) =>
      _forEncryption ? _encryptBlock(inp, inpOff, out, outOff) : _decryptBlock(inp, inpOff, out, outOff);

  int _encryptBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    if ((inpOff + blockSize) > inp.length) {
      throw new ArgumentError("Input buffer too short");
    }

    // XOR the cbcV and the input, then encrypt the cbcV
    for (int i = 0; i < blockSize; i++) {
      _cbcV[i] ^= inp[inpOff + i];
    }

    int length = _cipher.processBlock(_cbcV, 0, out, outOff);

    // copy ciphertext to cbcV
    _cbcV.setRange(0, blockSize, out.sublist(outOff));

    return length;
  }

  int _decryptBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) {

    if ((inpOff + blockSize) > inp.length) {
      throw new ArgumentError("Input buffer too short");
    }

    _cbcNextV.setRange(0, blockSize, inp.sublist(inpOff));

    int length = _cipher.processBlock(inp, inpOff, out, outOff);

    // XOR the cbcV and the output
    for (int i = 0; i < blockSize; i++) {
      out[outOff + i] ^= _cbcV[i];
    }

    // swap the back up buffer into next position
    Uint8List tmp;

    tmp = _cbcV;
    _cbcV = _cbcNextV;
    _cbcNextV = tmp;

    return length;
  }

}
