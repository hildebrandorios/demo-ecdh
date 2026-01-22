
import 'package:demo_ecdh/commons/ecdh.dart';
import 'package:flutter/material.dart';

class HomePage extends StatelessWidget {
  final TextEditingController inputMyPublicKey = TextEditingController();
  final TextEditingController inputOtherPublicKey = TextEditingController();
  final TextEditingController inputCommonKey = TextEditingController();
  final TextEditingController inputMessage = TextEditingController();
  final TextEditingController inputResult = TextEditingController();

  final ECDH ecdh = ECDH(curve: 'secp256k1');

  HomePage({super.key});

  @override
  Widget build(BuildContext context) {
    inputMyPublicKey.text = ecdh.publicKey;
    return Padding(
      padding: const EdgeInsets.all(8),
      child: Column(
        children: [
          TextFormField(
            controller: inputMyPublicKey,
            decoration: const InputDecoration(
              labelText: 'Mi clave publica',
              border: UnderlineInputBorder(),
            ),
            maxLines: 3,
          ),
          TextFormField(
            controller: inputOtherPublicKey,
            decoration: const InputDecoration(
              labelText: 'Otra clave publica',
              border: UnderlineInputBorder(),
            ),
            maxLines: 3,
          ),
          TextFormField(
            controller: inputCommonKey,
            decoration: const InputDecoration(
              labelText: 'Clave común',
              border: UnderlineInputBorder(),
            ),
            maxLines: 3,
          ),
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 8.0),
            child: SizedBox(
              width: double.infinity,
              child: TextButton(
                onPressed: () {
                  if (inputOtherPublicKey.text.isEmpty) {
                    showDialog(
                      context: context,
                      builder: (BuildContext context) => const AlertDialog(
                        title: Text('clave publica de tercero'),
                        content: Text(
                            'Se requiere una clave publica de un tercero para generar la clave comun'),
                      ),
                    );
                    return;
                  }
                  ecdh.agreement(otherPublicKeyPem: inputOtherPublicKey.text);
                  inputCommonKey.text = ecdh.commonsKey;
                },
                style: TextButton.styleFrom(
                  padding: const EdgeInsets.all(24),
                ),
                child: const Text('Generar clave común'),
              ),
            ),
          ),
          TextFormField(
            controller: inputMessage,
            decoration: const InputDecoration(
              labelText: 'Mensaje',
              border: UnderlineInputBorder(),
            ),
            maxLines: 3,
          ),
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 8.0),
            child: Row(
              children: [
                TextButton(
                  onPressed: () {
                    inputResult.text =
                        ecdh.encrypt(plaintext: inputMessage.text);
                  },
                  style: TextButton.styleFrom(
                    padding: const EdgeInsets.all(24),
                  ),
                  child: const Text('Encriptar'),
                ),
                TextButton(
                  onPressed: () {
                    inputResult.text =
                        ecdh.decrypt(plaintext: inputMessage.text);
                  },
                  style: TextButton.styleFrom(
                    padding: const EdgeInsets.all(24),
                  ),
                  child: const Text('Desencriptar'),
                ),
              ],
            ),
          ),
          TextFormField(
            controller: inputResult,
            decoration: const InputDecoration(
              labelText: 'Resultado',
              border: UnderlineInputBorder(),
            ),
            maxLines: 3,
          ),
        ],
      ),
    );
  }
}