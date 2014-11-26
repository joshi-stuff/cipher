// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.asymmetric.api;

import "dart:typed_data";

import "package:bignum/bignum.dart";
import "package:cipher/api.dart";

/// Base class for asymmetric keys in RSA
abstract class RSAAsymmetricKey implements AsymmetricKey {

  // The parameters of this key
  final BigInteger modulus;
  final BigInteger exponent;

  /// Create an asymmetric key for the given domain parameters
  RSAAsymmetricKey(this.modulus, this.exponent);

  /// Get modulus [n] = p·q
  BigInteger get n => modulus;

}

/// Private keys in RSA
class RSAPrivateKey extends RSAAsymmetricKey implements PrivateKey {

  // The secret prime factors of n
  final BigInteger p;
  final BigInteger q;

  BigInteger _dP;
  BigInteger _dQ;
  BigInteger _qInv;

  /// Create an RSA private key for the given parameters.
  RSAPrivateKey(BigInteger modulus, BigInteger exponent, this.p, this.q) : super(modulus, exponent);

  /// Get private exponent [d] = e^-1
  BigInteger get d => exponent;

  BigInteger get dP {
    _computeCRT();
    return _dP;
  }

  BigInteger get dQ {
    _computeCRT();
    return _dQ;
  }

  BigInteger get qInv {
    _computeCRT();
    return _qInv;
  }

  bool operator ==( other ) {
    if( other==null ) return false;
    if( other is! RSAPrivateKey ) return false;
    return (other.n==this.n) && (other.d==this.d);
  }

  int get hashCode => modulus.hashCode+exponent.hashCode;

  void _computeCRT() {
    if (_dP == null) {
      var pSub1 = (p - BigInteger.ONE);
      var qSub1 = (q - BigInteger.ONE);
      _dP = d.remainder(pSub1);
      _dQ = d.remainder(qSub1);
      _qInv = q.modInverse(p);
    }
  }

}

/// Public keys in RSA
class RSAPublicKey extends RSAAsymmetricKey implements PublicKey {

  /// Create an RSA public key for the given parameters.
  RSAPublicKey(BigInteger modulus, BigInteger exponent) : super(modulus, exponent);

  /// Get public exponent [e]
  BigInteger get e => exponent;

  bool operator ==( other ) {
    if( other==null ) return false;
    if( other is! RSAPublicKey ) return false;
    return (other.n==this.n) && (other.e==this.e);
  }

  int get hashCode => modulus.hashCode+exponent.hashCode;

}

/// A [Signature] created with RSA.
class RSASignature implements Signature {

  final Uint8List bytes;

  RSASignature(this.bytes);

  String toString() => bytes.toString();

  bool operator ==(other) {
    if( other==null ) return false;
    if( other is! RSASignature ) return false;
    if( other.bytes.length!=this.bytes.length ) return false;

    for (var i=0; i<this.bytes.length; i++) {
      if (this.bytes[i] != other.bytes[i]) {
        return false;
      }
    }
    return true;
  }

  int get hashCode => bytes.hashCode;

}

