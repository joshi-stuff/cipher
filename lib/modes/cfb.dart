// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.modes.cfb;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/block/base_block_cipher.dart";

/// Implementation of Cipher Feedback Mode (CFB) on top of a [BlockCipher].
class CFBBlockCipher extends BaseBlockCipher {

  final int _blockSize;
  final BlockCipher _cipher;

  final bool _forEncryption;
  final List<int> _iv;

  Uint8List _cfbV;
  Uint8List _cfbOutV;

  CFBBlockCipher(Map<Param, dynamic> params, BlockCipher cipher, int blockSize)
      : super("${cipher.algorithmName}/CFB-${blockSize*8}", params),
        _blockSize = blockSize,
        _cipher = cipher,
        _forEncryption = params[Param.ForEncryption],
        _iv = _normalizeIV(params[Param.IV], cipher.blockSize) {

    _cfbV = new Uint8List(_cipher.blockSize);
    _cfbOutV = new Uint8List(_cipher.blockSize);

    reset();
  }

  int get blockSize => _blockSize;

  void reset() {
    _cipher.reset();

    _cfbV.setRange(0, _iv.length, _iv);
    _cfbOutV.fillRange(0, _cfbOutV.length, 0);
  }

  /**
   * Process one block of input from the array in and write it to
   * the out array.
  *
   * @param in the array containing the input data.
   * @param inOff offset into the in array the data starts at.
   * @param out the array the output data will be copied into.
   * @param outOff the offset into the out array the output will start at.
   * @exception DataLengthException if there isn't enough data in in, or
   * space in out.
   * @exception IllegalStateException if the cipher isn't initialised.
   * @return the number of bytes processed and produced.
   */
  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) =>
      _forEncryption ? _encryptBlock(inp, inpOff, out, outOff) : _decryptBlock(inp, inpOff, out, outOff);

  static List<int> _normalizeIV(List<int> iv, int cipherBlockSize) {
    if (iv == null) {
      iv = [];
    }

    var normalizedIV = new List<int>(cipherBlockSize);

    if (iv.length < cipherBlockSize) {
      // prepend the supplied IV with zeros (per FIPS PUB 81)
      var offset = cipherBlockSize - iv.length;
      normalizedIV.fillRange(0, offset, 0);
      normalizedIV.setRange(offset, cipherBlockSize, iv);
    } else {
      normalizedIV.setRange(0, cipherBlockSize, iv);
    }

    return normalizedIV;
  }

  /**
   * Do the appropriate processing for CFB mode encryption.
   *
   * @param in the array containing the data to be encrypted.
   * @param inOff offset into the in array the data starts at.
   * @param out the array the encrypted data will be copied into.
   * @param outOff the offset into the out array the output will start at.
   * @exception DataLengthException if there isn't enough data in in, or
   * space in out.
   * @exception IllegalStateException if the cipher isn't initialised.
   * @return the number of bytes processed and produced.
   */
  int _encryptBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    if ((inpOff + blockSize) > inp.length) {
      throw new ArgumentError("Input buffer too short");
    }

    if ((outOff + blockSize) > out.length) {
      throw new ArgumentError("Output buffer too short");
    }

    _cipher.processBlock(_cfbV, 0, _cfbOutV, 0);

    // XOR the cfbV with the plaintext producing the ciphertext
    for (int i = 0; i < blockSize; i++) {
      out[outOff + i] = _cfbOutV[i] ^ inp[inpOff + i];
    }

    // change over the input block.
    var offset = _cfbV.length - blockSize;
    _cfbV.setRange(0, offset, _cfbV.sublist(blockSize));
    _cfbV.setRange(offset, _cfbV.length, out.sublist(outOff));

    return blockSize;
  }

  /**
   * Do the appropriate processing for CFB mode decryption.
  *
   * @param in the array containing the data to be decrypted.
   * @param inOff offset into the in array the data starts at.
   * @param out the array the encrypted data will be copied into.
   * @param outOff the offset into the out array the output will start at.
   * @exception DataLengthException if there isn't enough data in in, or
   * space in out.
   * @exception IllegalStateException if the cipher isn't initialised.
   * @return the number of bytes processed and produced.
   */
  int _decryptBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    if ((inpOff + blockSize) > inp.length) {
      throw new ArgumentError("Input buffer too short");
    }

    if ((outOff + blockSize) > out.length) {
      throw new ArgumentError("Output buffer too short");
    }

    _cipher.processBlock(_cfbV, 0, _cfbOutV, 0);

    // change over the input block.
    var offset = _cfbV.length - blockSize;
    _cfbV.setRange(0, offset, _cfbV.sublist(blockSize));
    _cfbV.setRange(offset, _cfbV.length, inp.sublist(inpOff));

    // XOR the cfbV with the ciphertext producing the plaintext
    for (int i = 0; i < blockSize; i++) {
      out[outOff + i] = _cfbOutV[i] ^ inp[inpOff + i];
    }

    return blockSize;
  }

}
