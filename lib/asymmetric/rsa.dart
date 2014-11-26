// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.asymmetric.rsa;

import "dart:typed_data";

import "package:bignum/bignum.dart";

import "package:cipher/api.dart";
import "package:cipher/asymmetric/base_asymmetric_block_cipher.dart";
import "package:cipher/asymmetric/api.dart";

class RSAEngine extends BaseAsymmetricBlockCipher {

  final bool _forEncryption;
  final RSAPrivateKey _privateKey;
  final RSAPublicKey _publicKey;

  RSAAsymmetricKey _key;

  RSAEngine(Map<Param, dynamic> params)
      : super("RSA", params),
        _forEncryption = params[Param.ForEncryption],
        _publicKey = params[Param.PublicKey],
        _privateKey = params[Param.PrivateKey] {

    if ((_publicKey != null) && (_privateKey != null)) {
      throw new ArgumentError("Only one key (public or private) must be provided as parameter");
    }

    if (_privateKey != null) {
      _key = _privateKey;
    } else {
      _key = _publicKey;
    }
  }

  void reset() {
  }

  int get inputBlockSize {
    var bitSize = _key.modulus.bitLength();
    if (_forEncryption) {
      return ((bitSize + 7) ~/ 8) - 1;
    } else {
      return (bitSize + 7) ~/ 8;
    }
  }

  int get outputBlockSize {
    var bitSize = _key.modulus.bitLength();
    if (_forEncryption) {
      return (bitSize + 7) ~/ 8;
    } else {
      return ((bitSize + 7) ~/ 8) - 1;
    }
  }

  int processBlock(Uint8List inp, int inpOff, int len, Uint8List out, int outOff) {
    var input = _convertInput(inp, inpOff, len);
    var output = _processBigInteger(input);
    return _convertOutput(output, out, outOff);
  }


  BigInteger _convertInput(Uint8List inp, int inpOff, int len) {
    var inpLen = inp.length;

    if (inpLen > (inputBlockSize + 1)) {
      throw new ArgumentError("Input too large for RSA cipher");
    }

    if ((inpLen == (inputBlockSize + 1)) && !_forEncryption) {
      throw new ArgumentError("Input too large for RSA cipher");
    }

    var res = new BigInteger.fromBytes(1, inp.sublist(inpOff, inpOff + len));
    if (res >= _key.modulus) {
      throw new ArgumentError("Input too large for RSA cipher");
    }

    return res;
  }

  int _convertOutput(BigInteger result, Uint8List out, int outOff) {
    final output = result.toByteArray();

    if (_forEncryption) {
      if ((output[0] == 0) &&
          (output.length > outputBlockSize)) { // have ended up with an extra zero byte, copy down.
        var len = (output.length - 1);
        out.setRange(outOff, outOff + len, output.sublist(1));
        return len;
      }
      if (output.length < outputBlockSize) { // have ended up with less bytes than normal, lengthen
        var len = outputBlockSize;
        out.setRange((outOff + len - output.length), (outOff + len), output);
        return len;
      }
    } else {
      if (output[0] == 0) { // have ended up with an extra zero byte, copy down.
        var len = (output.length - 1);
        out.setRange(outOff, outOff + len, output.sublist(1));
        return len;
      }
    }

    out.setAll(outOff, output);
    return output.length;
  }

  BigInteger _processBigInteger(BigInteger input) {
    if (_privateKey != null) {
      var mP, mQ, h, m;

      mP = (input.remainder(_privateKey.p)).modPow(_privateKey.dP, _privateKey.p);

      mQ = (input.remainder(_privateKey.q)).modPow(_privateKey.dQ, _privateKey.q);

      h = mP.subtract(mQ);
      h = h.multiply(_privateKey.qInv);
      h = h.mod(_privateKey.p);

      m = h.multiply(_privateKey.q);
      m = m.add(mQ);

      return m;
    } else {
      return input.modPow(_publicKey.exponent, _publicKey.modulus);
    }
  }

}
