// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.params.asymmetric_key_parameter;

import "package:cipher/api.dart";

/// Abstract [CipherParameters] to hold an asymmetric (public or private) key
abstract class AsymmetricKeyParameter<T extends AsymmetricKey> implements CipherParameters {

  final T key;

  AsymmetricKeyParameter(this.key);

}

/// A [CipherParameters] to hold an asymmetric public key
class PublicKeyParameter<T extends PublicKey> extends AsymmetricKeyParameter<T> {

  PublicKeyParameter(PublicKey key) : super(key);

}

/// A [CipherParameters] to hold an asymmetric private key
class PrivateKeyParameter<T extends PrivateKey> extends AsymmetricKeyParameter<T> {

  PrivateKeyParameter(PrivateKey key) : super(key);

}
