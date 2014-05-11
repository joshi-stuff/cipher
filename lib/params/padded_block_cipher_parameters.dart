// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.params.padded_block_cipher_parameters;

import "package:cipher/api.dart";

/**
 * [CipherParameters] for [PaddedBlockCipher]s consisting of two underlying [CipherParameters], one for the [BlockCipher] (of
 * type [UnderlyingCipherParameters]) and the other for the [Padding] (of type [PaddingCipherParameters]).
 */
class PaddedBlockCipherParameters<
    UnderlyingCipherParameters extends CipherParameters,
    PaddingCipherParameters extends CipherParameters
  > implements CipherParameters {

  final UnderlyingCipherParameters underlyingCipherParameters;
  final UnderlyingCipherParameters paddingCipherParameters;

  PaddedBlockCipherParameters( this.underlyingCipherParameters, this.paddingCipherParameters );

}
