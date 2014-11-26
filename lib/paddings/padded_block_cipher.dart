// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.paddings.padded_block_cipher;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/algorithm/base_algorithm.dart";

/// The standard implementation of [PaddedBlockCipher].
class PaddedBlockCipherImpl extends BaseParameterizedNamedAlgorithm implements PaddedBlockCipher {

  final Padding _padding;
  final BlockCipher _cipher;

  final bool _forEncryption;

  // TODO: revisar la composicion de parametros para que sea coherente con la creacion
  // TODO: quitar parametros en constructores de clases que no necesiten parametros
  PaddedBlockCipherImpl(Padding padding, BlockCipher cipher)
      : super("${cipher.algorithmName}/${padding.algorithmName}", {}),
        _padding = padding,
        _cipher = cipher,
        _forEncryption = cipher.parameters[Param.ForEncryption] {

    if (_forEncryption != _padding.parameters[Param.ForPadding]) {
      throw new ArgumentError(
          "Cipher and padding parameters ForEncryption and ForPadding must be synchronized");
    }

    if (_padding.parameters[Param.BlockSize] != _cipher.blockSize) {
      throw new ArgumentError(
          "Padding parameter BlockSize must have the same value as the cipher's block size");
    }
  }

  int get blockSize => _cipher.blockSize;

  void reset() {
    _cipher.reset();
  }

  Uint8List process(Uint8List data) {
    return _cipher.process(_padding.process(data));
    /*
    var inputBlocks = (data.length + blockSize - 1) ~/ blockSize;

    var outputBlocks;
    if (_forEncryption) {
      outputBlocks = (data.length + blockSize) ~/ blockSize;
    } else {
      if ((data.length % blockSize) != 0) {
        throw new ArgumentError("Input data length must be a multiple of cipher's block size");
      }
      outputBlocks = inputBlocks;
    }

    var out = new Uint8List(outputBlocks * blockSize);

    for (var i = 0; i < (inputBlocks - 1); i++) {
      var offset = (i * blockSize);
      processBlock(data, offset, out, offset);
    }

    var lastBlockOffset = ((inputBlocks - 1) * blockSize);
    var lastBlockSize = doFinal(data, lastBlockOffset, out, lastBlockOffset);

    return out.sublist(0, lastBlockOffset + lastBlockSize);
     */
  }

  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    return _cipher.processBlock(inp, inpOff, out, outOff);
  }

  int doFinal(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    var output = _cipher.process(_padding.process(inp.sublist(inpOff)));
    out.setAll(outOff, output);
    return output.length;
    /*
    if (_forEncryption) {
      var lastInputBlock = new Uint8List(blockSize)..setAll(0, inp.sublist(inpOff));

      var remainder = inp.length - inpOff;

      if (remainder < blockSize) {
        // Padding goes embedded in last block of data
        _padding.addPadding(lastInputBlock, (inp.length - inpOff));

        processBlock(lastInputBlock, 0, out, outOff);

        return blockSize;
      } else {
        // Padding goes alone in an additional block
        processBlock(inp, inpOff, out, outOff);

        _padding.addPadding(lastInputBlock, 0);

        processBlock(lastInputBlock, 0, out, outOff + blockSize);

        return 2 * blockSize;
      }
    } else {
      // Decrypt last block and remove padding
      processBlock(inp, inpOff, out, outOff);

      var padCount = padding.padCount(out.sublist(outOff));

      var padOffsetInBlock = blockSize - padCount;

      out.fillRange(outOff + padOffsetInBlock, out.length, 0);

      return padOffsetInBlock;
    }
     */
  }

}
