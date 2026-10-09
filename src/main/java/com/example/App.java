package com.example;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.NamedParameterSpec;
import java.nio.charset.StandardCharsets;

public class App {

    public static void main(String[] args) {
        try {
            // Generate a new ML-DSA-65 key pair directly in memory.
            KeyPairGenerator keyPairGenerator =
                    KeyPairGenerator.getInstance("ML-DSA");

            keyPairGenerator.initialize(
                    NamedParameterSpec.ML_DSA_65
            );

            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            System.out.println("ML-DSA key pair generated successfully");
            System.out.println("Public key algorithm: "
                    + publicKey.getAlgorithm());
            System.out.println("Public key format: "
                    + publicKey.getFormat());
            System.out.println("Private key algorithm: "
                    + privateKey.getAlgorithm());
            System.out.println("Private key format: "
                    + privateKey.getFormat());

            // Use the generated private key to sign some data.
            byte[] data = "Hello from ML-DSA"
                    .getBytes(StandardCharsets.UTF_8);

            Signature signer = Signature.getInstance("ML-DSA");
            signer.initSign(privateKey);
            signer.update(data);

            byte[] signature = signer.sign();

            System.out.println("Signature generated");
            System.out.println("Signature size: "
                    + signature.length + " bytes");

            // Use the generated public key to verify the signature.
            Signature verifier = Signature.getInstance("ML-DSA");
            verifier.initVerify(publicKey);
            verifier.update(data);

            boolean valid = verifier.verify(signature);

            System.out.println("Signature valid: " + valid);

        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }
}