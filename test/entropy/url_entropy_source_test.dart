// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.test.entropy.url_entropy_source_test;

import "package:cipher/cipher.dart";
import "package:cipher/impl/base.dart";
import "package:unittest/unittest.dart";

void main() {

  initCipher();

  var source = new EntropySource("https://www.random.org/cgi-bin/randbyte?nbytes={count}&format=f");
  const count = 1024;

  group( "${source.sourceName}:", () {

    test( "getBytes:", () {

      return source.getBytes(count).then( (bytes) {
        //print(bytes);
        expect( bytes.length, count );

        //var sum = bytes.fold(0, (prev, element) => prev + element);
        //var avg = sum/bytes.length;
        //print("AVG = $avg");
        //expect( avg>128-4, true );
        //expect( avg<128+4, true );
      });

    });

  });

}


