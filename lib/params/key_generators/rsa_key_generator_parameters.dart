// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.params.key_generators.rsa_key_generator_parameters;

import "package:bignum/bignum.dart";
import "package:cipher/api.dart";
import "package:cipher/params/key_generators/key_generator_parameters.dart";

/// Abstract [CipherParameters] to init an RSA key generator.
class RSAKeyGeneratorParameters extends KeyGeneratorParameters {

  final BigInteger publicExponent;
  final int certainty;

  RSAKeyGeneratorParameters(this.publicExponent, int bitStrength, this.certainty) : super(bitStrength);

}
