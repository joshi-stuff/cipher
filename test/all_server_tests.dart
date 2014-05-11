// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.test.all_server_tests;

//import "./entropy/file_entropy_source_test.dart" as dev_random_entropy_source_test;
//import "./entropy/url_entropy_source_test.dart" as random_org_entropy_source_test;

import "./all_tests.dart" as all_tests;
import "./api/registry_server_test.dart" as registry_server_test;

/// Some tests are commented out because they need external dependencies and thus, cannot be run automatically.
void main() {

  // registry
  registry_server_test.main();

  // base tests
  all_tests.main();

  // entropy sources
  //dev_random_entropy_source_test.main();
  //random_org_entropy_source_test.main();

}