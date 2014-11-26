// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.macs.hmac;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/macs/base_mac.dart";

/// HMAC implementation based on RFC2104: H(K XOR opad, H(K XOR ipad, text))
class HMac extends BaseMac {

  static final _IPAD = 0x36;
  static final _OPAD = 0x5C;

  final Digest _digest;
  final int _blockLength;

  final List<int> _key;

  Uint8List _inputPad;
  Uint8List _outputBuf;

  HMac(Map<Param, dynamic> params, Digest digest, this._blockLength)
      : super("${digest.algorithmName}/HMAC", params),
        _digest = digest,
        _key = params[Param.Key] {

    _inputPad = new Uint8List(_blockLength);
    _outputBuf = new Uint8List(_blockLength + macSize);

    reset();
  }

  int get macSize => _digest.digestSize;

  void reset() {
    _digest.reset();

    _digestFirstRound();
  }

  void updateByte(int inp) {
    _digest.updateByte(inp);
  }

  void update(Uint8List inp, int inpOff, int len) {
    _digest.update(inp, inpOff, len);
  }

  int doFinal(Uint8List out, int outOff) {
    _digest.doFinal(_outputBuf, _blockLength);
    _digest.update(_outputBuf, 0, _outputBuf.length);

    var len = _digest.doFinal(out, outOff);
    _outputBuf.fillRange(_blockLength, _outputBuf.length, 0);
    _digest.update(_inputPad, 0, _inputPad.length);

    return len;
  }

  void _digestFirstRound() {
    if (_key.length > _blockLength) {
      _digest.update(_key, 0, _key.length);
      _digest.doFinal(_inputPad, 0);

      _key.length = macSize;
    } else {
      _inputPad.setRange(0, _key.length, _key);
    }

    _inputPad.fillRange(_key.length, _inputPad.length, 0);

    _outputBuf.setRange(0, _blockLength, _inputPad);

    _xorPad(_inputPad, _blockLength, _IPAD);
    _xorPad(_outputBuf, _blockLength, _OPAD);

    _digest.update(_inputPad, 0, _inputPad.length);
  }

  void _xorPad(Uint8List pad, int len, int n) {
    for (var i = 0; i < len; i++) {
      pad[i] ^= n;
    }
  }

}
