// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.test.api.registry_server_test;

import "package:cipher/impl/server.dart";
import "package:unittest/unittest.dart";

import "../test/registry_tests.dart";

void main() {

  initCipher();

  group( "registry_server:", () {

    test( "EntropySource returns valid implementations", () {

      testEntropySource( "file:///dev/random" );
      testEntropySource( "http://www.random.org/cgi-bin/randbyte?nbytes={count}&format=f" );
      testEntropySource( "https://www.random.org/cgi-bin/randbyte?nbytes={count}&format=f" );

    });

  });

}
