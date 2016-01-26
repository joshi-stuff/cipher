// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

part of cipher.impl;

void _registerAsymmetricBlockCiphers() {
  AsymmetricBlockCipher.registry.registerDynamicFactory(_pkcs1AsymmetricBlockCipherFactory);
  AsymmetricBlockCipher.registry["RSA"] = (name, params) => new RSAEngine(params);
}

void _registerBlockCiphers() {
  BlockCipher.registry["AES"] = (name, params) => new AESFastEngine(params);
}

void _registerDigests() {
  Digest.registry["MD2"] = (name, params) => new MD2Digest(params);
  Digest.registry["MD4"] = (name, params) => new MD4Digest(params);
  Digest.registry["MD5"] = (name, params) => new MD5Digest(params);
  Digest.registry["RIPEMD-128"] = (name, params) => new RIPEMD128Digest(params);
  Digest.registry["RIPEMD-160"] = (name, params) => new RIPEMD160Digest(params);
  Digest.registry["RIPEMD-256"] = (name, params) => new RIPEMD256Digest(params);
  Digest.registry["RIPEMD-320"] = (name, params) => new RIPEMD320Digest(params);
  Digest.registry["SHA-1"] = (name, params) => new SHA1Digest(params);
  Digest.registry["SHA-224"] = (name, params) => new SHA224Digest(params);
  Digest.registry["SHA-256"] = (name, params) => new SHA256Digest(params);
  Digest.registry["SHA-384"] = (name, params) => new SHA384Digest(params);
  Digest.registry["SHA-512"] = (name, params) => new SHA512Digest(params);
  Digest.registry["Tiger"] = (name, params) => new TigerDigest(params);
  Digest.registry["Whirlpool"] = (name, params) => new WhirlpoolDigest(params);
  Digest.registry.registerDynamicFactory(_sha3DigestFactory);
  Digest.registry.registerDynamicFactory(_sha512tDigestFactory);
}

// See part ecc_curves.dart for _registerEccStandardCurves()

void _registerKeyDerivators() {
  KeyDerivator.registry["scrypt"] = (name, params) => new Scrypt(params);
  KeyDerivator.registry.registerDynamicFactory(_pbkdf2KeyDerivatorFactory);
}

void _registerKeyGenerators() {
  KeyGenerator.registry.registerDynamicFactory(_ecKeyGeneratorFactory);
  KeyGenerator.registry.registerDynamicFactory(new MultiplexFactory({
    1: new ConcreteAlgorithmFactory(
        "RSA",
        (params, _) => new RSAKeyGenerator(params, new SecureRandom())),
    2: new SecureRandomFactory()..chain(
        new ConcreteAlgorithmFactory("RSA", (params, random) => new RSAKeyGenerator(params, random))),
  }));
}


void _registerMacs() {
  Mac.registry["GOST3411/HMAC"] = (name, params) => new HMac(params, new Digest("GOST3411"), 32);
  Mac.registry["MD2/HMAC"] = (name, params) => new HMac(params, new Digest("MD2"), 16);
  Mac.registry["MD4/HMAC"] = (name, params) => new HMac(params, new Digest("MD4"), 64);
  Mac.registry["MD5/HMAC"] = (name, params) => new HMac(params, new Digest("MD5"), 64);
  Mac.registry["RIPEMD-128/HMAC"] =
      (name, params) => new HMac(params, new Digest("RIPEMD-128"), 64);
  Mac.registry["RIPEMD-160/HMAC"] =
      (name, params) => new HMac(params, new Digest("RIPEMD-160"), 64);
  Mac.registry["SHA-1/HMAC"] = (name, params) => new HMac(params, new Digest("SHA-1"), 64);
  Mac.registry["SHA-224/HMAC"] = (name, params) => new HMac(params, new Digest("SHA-224"), 64);
  Mac.registry["SHA-256/HMAC"] = (name, params) => new HMac(params, new Digest("SHA-256"), 64);
  Mac.registry["SHA-384/HMAC"] = (name, params) => new HMac(params, new Digest("SHA-384"), 128);
  Mac.registry["SHA-512/HMAC"] = (name, params) => new HMac(params, new Digest("SHA-512"), 128);
  Mac.registry["Tiger/HMAC"] = (name, params) => new HMac(params, new Digest("Tiger"), 64);
  Mac.registry["Whirlpool/HMAC"] = (name, params) => new HMac(params, new Digest("Whirlpool"), 64);
}

void _registerModesOfOperation() {
  BlockCipher.registry.registerDynamicFactory(
      (name, params) =>
          _modeOfOperationFactory(
              name,
              params,
              "CBC",
              (cipher, params) => new CBCBlockCipher(params, cipher)));
  BlockCipher.registry.registerDynamicFactory(
      (name, params) =>
          _variableSizeModeOfOperationFactory(
              name,
              params,
              "CFB",
              (blockSize, cipher, params) => new CFBBlockCipher(params, cipher, blockSize)));
  BlockCipher.registry.registerDynamicFactory(
      (name, params) =>
          _modeOfOperationFactory(
              name,
              params,
              "CTR",
              (cipher, params) =>
                  new StreamCipherAsBlockCipher(params, new CTRStreamCipher(params, cipher), cipher.blockSize)));
  BlockCipher.registry.registerDynamicFactory(
      (name, params) =>
          _modeOfOperationFactory(
              name,
              params,
              "ECB",
              (cipher, params) => new ECBBlockCipher(params, cipher)));
  BlockCipher.registry.registerDynamicFactory(
      (name, params) =>
          // TODO: Pass forEncryption=true always to underlying cipher (remove commented init() from GCTR)
  _modeOfOperationFactory(
      name,
      params,
      "GCTR",
      (cipher, params) => new GCTRBlockCipher(params, cipher)));
  BlockCipher.registry.registerDynamicFactory(
      (name, params) =>
          _variableSizeModeOfOperationFactory(
              name,
              params,
              "OFB",
              (blockSize, cipher, params) => new OFBBlockCipher(params, cipher, blockSize)));
  BlockCipher.registry.registerDynamicFactory(
      (name, params) =>
          _modeOfOperationFactory(
              name,
              params,
              "SIC",
              (cipher, params) =>
                  new StreamCipherAsBlockCipher(params, new SICStreamCipher(params, cipher), cipher.blockSize)));
}

void _registerPaddedBlockCiphers() {
  PaddedBlockCipher.registry.registerDynamicFactory(_paddedBlockCipherFactory);
}

void _registerPaddings() {
  Padding.registry["PKCS7"] = (name, params) => new PKCS7Padding(params);
}

void _registerSecureRandoms() {
  SecureRandom.registry["Fortuna"] = (name, params) => new FortunaRandom();
  SecureRandom.registry.registerDynamicFactory(_ctrPrngSecureRandomFactory);
  SecureRandom.registry.registerDynamicFactory(_ctrAutoSeedPrngSecureRandomFactory);
}

void _registerSigners() {
  Signer.registry.registerDynamicFactory(_ecdsaSignerFactory);
  Signer.registry["MD2/RSA"] =
      (name, params) => new RSASigner(new Digest("MD2"), "06082a864886f70d0202");
  Signer.registry["MD4/RSA"] =
      (name, params) => new RSASigner(new Digest("MD4"), "06082a864886f70d0204");
  Signer.registry["MD5/RSA"] =
      (name, params) => new RSASigner(new Digest("MD5"), "06082a864886f70d0205");
  Signer.registry["RIPEMD-128/RSA"] =
      (name, params) => new RSASigner(new Digest("RIPEMD-128"), "06052b24030202");
  Signer.registry["RIPEMD-160/RSA"] =
      (name, params) => new RSASigner(new Digest("RIPEMD-160"), "06052b24030201");
  Signer.registry["RIPEMD-256/RSA"] =
      (name, params) => new RSASigner(new Digest("RIPEMD-256"), "06052b24030203");
  Signer.registry["SHA-1/RSA"] =
      (name, params) => new RSASigner(new Digest("SHA-1"), "06052b0e03021a");
  Signer.registry["SHA-224/RSA"] =
      (name, params) => new RSASigner(new Digest("SHA-224"), "0609608648016503040204");
  Signer.registry["SHA-256/RSA"] =
      (name, params) => new RSASigner(new Digest("SHA-256"), "0609608648016503040201");
  Signer.registry["SHA-384/RSA"] =
      (name, params) => new RSASigner(new Digest("SHA-384"), "0609608648016503040202");
  Signer.registry["SHA-512/RSA"] =
      (name, params) => new RSASigner(new Digest("SHA-512"), "0609608648016503040203");
}

void _registerStreamCiphers() {
  StreamCipher.registry["Salsa20"] = (name, params) => new Salsa20Engine();
  StreamCipher.registry.registerDynamicFactory(_ctrStreamCipherFactory);
  StreamCipher.registry.registerDynamicFactory(_sicStreamCipherFactory);
}

////////////////////////////////////////////////////////////////////////////////////////////////////

//// random+asymmetric+algorithm

AsymmetricBlockCipher _pkcs1AsymmetricBlockCipherFactory(String name, Map<Param, dynamic> params) {
  var names = name.split("/");

  if ((names.length != 2) && (names.length != 3)) return null;
  if (names.last != "PKCS1") return null;

  var unchainedParams = Param.split(params, names.length);

  var random, cipher;
  switch (names.length) {
    case 2:
      random = new SecureRandom();
      cipher = _createOrNull(() => new AsymmetricBlockCipher(names[0], unchainedParams[0]));
      break;

    case 3:
      random = new SecureRandom(names[0]);
      cipher = _createOrNull(() => new AsymmetricBlockCipher(names[1], unchainedParams[1]));
      break;
  }

  return new PKCS1Encoding(random, cipher, unchainedParams.last);
}

//// random+algorithm

KeyGenerator _ecKeyGeneratorFactory(String name, Map<Param, dynamic> params) {
  var names = name.split("/");

  if ((names.length != 1) && (names.length != 2)) return null;
  if (names.last != "EC") return null;

  var unchainedParams = Param.split(params, names.length);

  var random;
  switch (names.length) {
    case 1:
      random = new SecureRandom();
      break;

    case 2:
      random = new SecureRandom(names[0]);
      break;
  }

  return new ECKeyGenerator(unchainedParams.last, random);
}

KeyGenerator _rsaKeyGeneratorFactory(String name, Map<Param, dynamic> params) {
  var names = name.split("/");

  if ((names.length != 1) && (names.length != 2)) return null;
  if (names.last != "RSA") return null;

  var unchainedParams = Param.split(params, names.length);

  var random;
  switch (names.length) {
    case 1:
      random = new SecureRandom();
      break;

    case 2:
      random = new SecureRandom(names[0]);
      break;
  }

  return new RSAKeyGenerator(unchainedParams.last, random);
}


// mac+algorithm

KeyDerivator _pbkdf2KeyDerivatorFactory(String name, Map<Param, dynamic> params) {
  var names = name.split("/");

  if (names.length < 2) return null;
  if (names.last != "PBKDF2") return null;

  var mac = _createOrNull(() => new Mac(names.sublist(0, names.length - 1).join("/")));
  if (mac != null) {
    return new PBKDF2KeyDerivator(params, mac);
  }

  return null;
}

// blockcipher+algorithm
BlockCipher _modeOfOperationFactory(String name, Map<Param, dynamic> params, String modeName,
    BlockCipher subFactory(BlockCipher cipher, Map<Param, dynamic> params)) {

  var names = name.split("/");

  if (names.length != 2) return null;
  if (names[1] != modeName) return null;

  var unchainedParams = Param.split(params, 2);

  var cipher = _createOrNull(() => new BlockCipher(names[0], unchainedParams[0]));

  if (cipher != null) {
    return subFactory(cipher, unchainedParams[1]);
  }

  return null;
}

PaddedBlockCipher _paddedBlockCipherFactory(String name, Map<Param, dynamic> params) {
  var names = name.split("/");

  var unchainedParams = Param.split(params, names.length);

  var padding = _createOrNull(() => new Padding(names.last, unchainedParams.last));

  if (padding != null) {
    var popchainedParams = Param.merge(unchainedParams.sublist(0, unchainedParams.length - 1));

    var cipher = _createOrNull(
        () => new BlockCipher(names.sublist(0, names.length - 1).join("/"), popchainedParams));

    if (cipher != null) {
      return new PaddedBlockCipherImpl(padding, cipher);
    }
  }

  return null;
}
StreamCipher _ctrStreamCipherFactory(String name, Map<Param, dynamic> params) {
  var names = name.split("/");

  if (names.length != 2) return null;
  if (names[1] != "CTR") return null;

  var unchainedParams = Param.split(params, 2);

  var cipher = _createOrNull(() => new BlockCipher(names[0], unchainedParams[0]));

  if (cipher != null) {
    return new CTRStreamCipher(unchainedParams[1], cipher);
  }

  return null;
}

StreamCipher _sicStreamCipherFactory(String name, Map<Param, dynamic> params) {
  var names = name.split("/");

  if (names.length != 2) return null;
  if (names[1] != "SIC") return null;

  var unchainedParams = Param.split(params, 2);

  var cipher = _createOrNull(() => new BlockCipher(names[0], unchainedParams[0]));

  if (cipher != null) {
    return new SICStreamCipher(unchainedParams[1], cipher);
  }

  return null;
}

// bitlength blockcipher+algorithm; TODO: move bitlength to parameters
BlockCipher _variableSizeModeOfOperationFactory(String name, Map<Param, dynamic> params,
    String modeName, BlockCipher subFactory(int blockSize, BlockCipher cipher, Map<Param,
    dynamic> params)) {

  var names = name.split("/");

  if (names.length != 2) return null;
  if (!names[1].startsWith(modeName + "-")) return null;

  var namesOf1Parts = names[1].split("-");

  var blockSizeInBits = int.parse(namesOf1Parts[1]);
  if ((blockSizeInBits % 8) != 0) {
    throw new ArgumentError(
        "Bad ${modeName} block size: $blockSizeInBits (must be a multiple of 8)");
  }

  var unchainedParams = Param.split(params, 2);

  var cipher = _createOrNull(() => new BlockCipher(names[0], unchainedParams[0]));

  if (cipher != null) {
    return subFactory(blockSizeInBits ~/ 8, cipher, unchainedParams[1]);
  }

  return null;
}

BlockCipher _cfbBlockCipherFactory(String name, Map<Param, dynamic> params) {
  var parts = name.split("/");

  if (parts.length != 2) return null;
  if (!parts[1].startsWith("CFB-")) return null;

  var blockSizeInBits = int.parse(parts[1].substring(4));
  if ((blockSizeInBits % 8) != 0) {
    throw new ArgumentError("Bad CFB block size: $blockSizeInBits (must be a multiple of 8)");
  }

  var underlyingCipher = _createOrNull(() => new BlockCipher(parts[0], params));

  if (underlyingCipher != null) {
    return new CFBBlockCipher(underlyingCipher, blockSizeInBits ~/ 8);
  }

  return null;
}

BlockCipher _ofbBlockCipherFactory(String name, Map<Param, dynamic> params) {
  var parts = name.split("/");

  if (parts.length != 2) return null;
  if (!parts[1].startsWith("OFB-")) return null;

  var blockSizeInBits = int.parse(parts[1].substring(4));
  if ((blockSizeInBits % 8) != 0) {
    throw new ArgumentError("Bad OFB block size: $blockSizeInBits (must be a multiple of 8)");
  }

  var underlyingCipher = _createOrNull(() => new BlockCipher(parts[0], params));

  if (underlyingCipher != null) {
    return new OFBBlockCipher(underlyingCipher, blockSizeInBits ~/ 8);
  }

  return null;
}

//// bitlength digest; TODO: move bitlength to parameters

Digest _sha512tDigestFactory(String name, Map<Param, dynamic> params) {
  if (!name.startsWith("SHA-512-")) return null;

  var bitLength = int.parse(name.substring(8));
  if ((bitLength % 8) != 0) {
    throw new ArgumentError("Digest length for SHA-512/t is not a multiple of 8: ${bitLength}");
  }

  return new SHA512tDigest(params, bitLength ~/ 8);
}

Digest _sha3DigestFactory(String name, Map<Param, dynamic> params) {
  if (!name.startsWith("SHA-3-")) return null;

  var bitLength = int.parse(name.substring(6));

  return new SHA3Digest(params, bitLength);
}

/////////////////////



SecureRandom _ctrPrngSecureRandomFactory(String name, Map<Param, dynamic> params) {
  if (name.endsWith("/CTR/PRNG")) {
    var blockCipherName = name.substring(0, name.length - 9);
    var blockCipher = _createOrNull(() => new BlockCipher(blockCipherName, params));
    return new BlockCtrRandom(blockCipher);
  }

  return null;
}

SecureRandom _ctrAutoSeedPrngSecureRandomFactory(String name, Map<Param, dynamic> params) {
  if (name.endsWith("/CTR/AUTO-SEED-PRNG")) {
    var blockCipherName = name.substring(0, name.length - 19);
    var blockCipher = _createOrNull(() => new BlockCipher(blockCipherName, params));
    return new AutoSeedBlockCtrRandom(blockCipher);
  }

  return null;
}

Signer _ecdsaSignerFactory(String name, Map<Param, dynamic> params) {
  var sep = name.lastIndexOf("/");

  if (sep == -1) return null;

  var ecdsaName = name.substring(sep + 1);
  if ((ecdsaName != "ECDSA") && (ecdsaName != "DET-ECDSA")) return null;

  var digestName = name.substring(0, sep);

  var underlyingDigest = _createOrNull(() => new Digest(digestName));

  if (underlyingDigest != null) {
    var mac = null;
    if (ecdsaName == "DET-ECDSA") {
      mac = new Mac("${digestName}/HMAC");
    }

    return new ECDSASigner(underlyingDigest, mac);
  }

  return null;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
dynamic _createOrNull(closure()) {
  try {
    return closure();
  } on UnsupportedError catch (e) {
    return null;
  }
}
