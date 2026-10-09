package com.example;

import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.NamedParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

public class App {

        private static final Path CERTIFICATE_DIRECTORY = Paths.get("certificates");

        private static final Path CERTIFICATE_PATH = CERTIFICATE_DIRECTORY.resolve("mldsa-certificate.pem");

        public static void main(String[] args) {
                try {
                        /*
                         * 1. Generate an ML-DSA key pair in memory.
                         */
                        KeyPair keyPair = generateMLDSAKeyPair();

                        /*
                         * 2. Create a self-signed certificate.
                         */
                        X509Certificate generatedCertificate = createSelfSignedCertificate(keyPair);

                        /*
                         * 3. Save the certificate in the hard-coded directory.
                         */
                        saveCertificate(generatedCertificate);

                        /*
                         * 4. Pick up the certificate from the directory.
                         */
                        X509Certificate loadedCertificate = loadCertificate();

                        printCertificate(loadedCertificate);

                        /*
                         * 5. Use the certificate.
                         *
                         * Sign with the in-memory private key and verify using
                         * the public key obtained from the loaded certificate.
                         */
                        useCertificate(keyPair, loadedCertificate);

                } catch (Exception exception) {
                        System.err.println("Application failed:");
                        exception.printStackTrace();
                }
        }

        private static KeyPair generateMLDSAKeyPair()
                        throws Exception {

                KeyPairGenerator generator = KeyPairGenerator.getInstance("ML-DSA");

                generator.initialize(
                                NamedParameterSpec.ML_DSA_65);

                KeyPair keyPair = generator.generateKeyPair();

                System.out.println("1. ML-DSA key pair generated");
                System.out.println(
                                "   Public key algorithm: "
                                                + keyPair.getPublic().getAlgorithm());

                return keyPair;
        }

        private static X509Certificate createSelfSignedCertificate(KeyPair keyPair) throws Exception {
                Instant now = Instant.now();
                Date validFrom = Date.from(now.minus(1, ChronoUnit.MINUTES));
                Date validUntil = Date.from(now.plus(365, ChronoUnit.DAYS));
                CertificateValidity validity = new CertificateValidity(validFrom, validUntil);
                BigInteger serialNumber = new BigInteger(128, new SecureRandom()).abs();
                X500Name owner = new X500Name(
                                "CN=ML-DSA Test Certificate," + " OU=Development," + " O=Example," + " C=IN");
                X509CertInfo certificateInfo = new X509CertInfo();
                certificateInfo.setVersion(new CertificateVersion(CertificateVersion.V3));
                certificateInfo.setSerialNumber(new CertificateSerialNumber(serialNumber));
                certificateInfo.setSubject(owner);
                certificateInfo.setIssuer(owner);
                certificateInfo.setValidity(validity);
                certificateInfo.setKey(new CertificateX509Key(keyPair.getPublic()));
                X509Certificate certificate = X509CertImpl.newSigned(certificateInfo, keyPair.getPrivate(), "ML-DSA");
                System.out.println("2. Self-signed ML-DSA certificate created");
                return certificate;
        }

        private static void saveCertificate(
                        X509Certificate certificate) throws Exception {

                Files.createDirectories(CERTIFICATE_DIRECTORY);

                String pemCertificate = toPem(
                                "CERTIFICATE",
                                certificate.getEncoded());

                Files.writeString(
                                CERTIFICATE_PATH,
                                pemCertificate,
                                StandardCharsets.US_ASCII);

                System.out.println(
                                "3. Certificate saved to: "
                                                + CERTIFICATE_PATH.toAbsolutePath());
        }

        private static X509Certificate loadCertificate()
                        throws Exception {

                try (InputStream inputStream = Files.newInputStream(CERTIFICATE_PATH)) {

                        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

                        X509Certificate certificate = (X509Certificate) certificateFactory
                                        .generateCertificate(inputStream);

                        System.out.println(
                                        "4. Certificate loaded from directory");

                        return certificate;
                }
        }

        private static void useCertificate(
                        KeyPair keyPair,
                        X509Certificate certificate) throws Exception {

                byte[] data = "This data is signed using ML-DSA"
                                .getBytes(StandardCharsets.UTF_8);

                /*
                 * Sign using the generated private key.
                 */
                Signature signer = Signature.getInstance("ML-DSA");

                signer.initSign(keyPair.getPrivate());
                signer.update(data);

                byte[] digitalSignature = signer.sign();

                /*
                 * Verify using the public key from the loaded certificate.
                 */
                Signature verifier = Signature.getInstance("ML-DSA");

                verifier.initVerify(certificate.getPublicKey());
                verifier.update(data);

                boolean signatureValid = verifier.verify(digitalSignature);

                /*
                 * Also verify that the certificate was self-signed.
                 */
                certificate.checkValidity();
                certificate.verify(certificate.getPublicKey());

                System.out.println("5. Certificate used successfully");
                System.out.println(
                                "   Data: "
                                                + new String(data, StandardCharsets.UTF_8));
                System.out.println(
                                "   Signature size: "
                                                + digitalSignature.length
                                                + " bytes");
                System.out.println(
                                "   Digital signature valid: "
                                                + signatureValid);
                System.out.println(
                                "   Self-signed certificate valid: true");
        }

        private static void printCertificate(
                        X509Certificate certificate) {
                System.out.println();
                System.out.println("Loaded certificate details:");
                System.out.println(
                                "Subject: "
                                                + certificate.getSubjectX500Principal());
                System.out.println(
                                "Issuer: "
                                                + certificate.getIssuerX500Principal());
                System.out.println(
                                "Serial number: "
                                                + certificate.getSerialNumber());
                System.out.println(
                                "Valid from: "
                                                + certificate.getNotBefore());
                System.out.println(
                                "Valid until: "
                                                + certificate.getNotAfter());
                System.out.println(
                                "Signature algorithm: "
                                                + certificate.getSigAlgName());
                System.out.println(
                                "Public key algorithm: "
                                                + certificate.getPublicKey().getAlgorithm());
                System.out.println();
        }

        private static String toPem(
                        String type,
                        byte[] derData) {
                String base64 = Base64.getMimeEncoder(
                                64,
                                "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(derData);

                return "-----BEGIN " + type + "-----\n"
                                + base64
                                + "\n-----END " + type + "-----\n";
        }
}