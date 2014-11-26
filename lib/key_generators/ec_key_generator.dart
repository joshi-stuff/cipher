// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.key_generators.ec_key_generator;

import "package:bignum/bignum.dart";

import "package:cipher/api.dart";
import "package:cipher/algorithm/base_algorithm.dart";
import "package:cipher/ecc/api.dart";
import "package:cipher/key_generators/api.dart";

/// Abstract [CipherParameters] to init an ECC key generator.
class ECKeyGenerator extends BaseParameterizedNamedAlgorithm implements KeyGenerator {

  final SecureRandom _random;

  final ECDomainParameters _domainParameters;

  ECKeyGenerator(Map<Param, dynamic> params, this._random)
      : super("EC", params),
        _domainParameters = params[ECKeyGeneratorParam.DomainParameters];

  AsymmetricKeyPair generateKeyPair() {
    var n = _domainParameters.n;
    var nBitLength = n.bitLength();
    var d;

    do {
      d = _random.nextBigInteger(nBitLength);
    } while (d == BigInteger.ZERO || (d >= n));

    var Q = _domainParameters.G * d;

    return new AsymmetricKeyPair(
        new ECPublicKey(Q, _domainParameters),
        new ECPrivateKey(d, _domainParameters));
  }

}
