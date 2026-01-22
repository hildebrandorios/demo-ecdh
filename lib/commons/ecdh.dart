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
    random.seed(KeyParameter(_generateSecureRandom(length: 32, randomValue: 255)));
    return random;
  }

  Uint8List _generateSecureRandom({required int length, required int randomValue}) {
    final secureRandom = Random.secure();
    final random =
        List<int>.generate(length, (i) => secureRandom.nextInt(randomValue));
    return Uint8List.fromList(random);
  }
  
}