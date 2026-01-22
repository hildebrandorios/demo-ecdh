import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart';
import 'package:pointycastle/export.dart';
import 'package:pointycastle/key_generators/api.dart';
import 'package:pointycastle/key_generators/ec_key_generator.dart';

class ECDH {
  late AsymmetricKeyPair<ECPublicKey, ECPrivateKey> _keyPair;
  List<int>? _secretShared;

  String get publicKey {
    return CryptoUtils.encodeEcPublicKeyToPem(_keyPair.publicKey);
  }

  String get privateKey {
    return CryptoUtils.encodeEcPrivateKeyToPem(_keyPair.privateKey);
  }

  String get commonsKey {
    return _secretShared == null ? '' : base64.encode(_secretShared!);
  }

  ECDH({required String curve}) {
    final ECDomainParameters ecDomain = ECDomainParameters(curve);
    final keyParams = ECKeyGeneratorParameters(ecDomain);
    final generator = ECKeyGenerator();
    final params = ParametersWithRandom<ECKeyGeneratorParameters>(
      keyParams,
      _getSecureRandomForKey(),
    );
    generator.init(params);
    _keyPair = generator.generateKeyPair();
  }

  SecureRandom _getSecureRandomForKey() {
    SecureRandom random = FortunaRandom();
    random.seed(
      KeyParameter(_generateSecureRandom(length: 32, randomValue: 255)),
    );
    return random;
  }

  Uint8List _generateSecureRandom({
    required int length,
    required int randomValue,
  }) {
    final secureRandom = Random.secure();
    final random = List<int>.generate(
      length,
      (i) => secureRandom.nextInt(randomValue),
    );
    return Uint8List.fromList(random);
  }

  void agreement({required String otherPublicKeyPem}) {
    // final otherPublicKey =
    //     CryptoUtils.parseEcPublicKeyFromPem(otherPublicKeyPem);
    // final agreement = ECDHBasicAgreement();
    // agreement.init(_keyPair.privateKey);
    // final sharedSecret = agreement.calculateAgreement(otherPublicKey);
    // final sharedSecretBytes = _bigIntToUint8List(sharedSecret);
    // _secretShared = sharedSecretBytes;

    final agremment = ECDHBasicAgreement();
    agremment.init(_keyPair.privateKey);

    final commonShared = agremment.calculateAgreement(
      CryptoUtils.ecPublicKeyFromPem(otherPublicKeyPem),
    );

    _secretShared = commonShared.toRadixString(16).codeUnits;
  }

  String encrypt({required String plaintext}) {
    final sha256 = Digest('SHA-256');
    final iv = _generateSecureRandom(length: 12, randomValue: 256);
    final salt = _generateSecureRandom(length: 16, randomValue: 256);
    final secretHash = sha256.process(
      Uint8List.fromList([...salt, ..._secretShared!]),
    );

    final params = AEADParameters(
      KeyParameter(secretHash),
      128,
      iv,
      Uint8List(0),
    );

    final cipher = GCMBlockCipher(AESEngine())..init(true, params);

    final textBytes = utf8.encode(plaintext);
    final ciphertext = cipher.process(Uint8List.fromList(textBytes));

    return base64.encode(Uint8List.fromList([...iv, ...salt, ...ciphertext]));
  }

  String decrypt({required String plaintext}) {
    final sha256 = Digest('SHA-256');
    final encryptTextBase64 = base64.decode(plaintext);
    Uint8List iv = encryptTextBase64.sublist(0, 12);
    Uint8List salt = encryptTextBase64.sublist(12, 28);
    final secretHash =
        sha256.process(Uint8List.fromList([...salt, ..._secretShared!]));

    final params =
        AEADParameters(KeyParameter(secretHash), 128, iv, Uint8List(0));

    final cipher = GCMBlockCipher(AESEngine())..init(false, params);
    final decryptedText = cipher.process(encryptTextBase64.sublist(28));

    return utf8.decode(decryptedText);
  }
}
