package com.example;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import javax.crypto.spec.DHParameterSpec;

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

public class App {

    private static final Path CERTIFICATE_DIRECTORY =
            Paths.get("certificates");

    private static final Path CERTIFICATE_PATH =
            CERTIFICATE_DIRECTORY.resolve("certificate.pem");

    private static final String LOCAL_PROVIDER_NAME = "BC";

    /** A runnable that is allowed to throw. */
    @FunctionalInterface
    private interface CheckedRunnable {
        void run() throws Exception;
    }

    // ------------------------------------------------------------------
    // main
    // ------------------------------------------------------------------

    public static void main(String[] args) {
        // Register Bouncy Castle once, up front. Needed for the "BC"
        // provider lookups and for the single-argument ML-KEM / ML-DSA
        // getInstance() calls.
        registerBouncyCastleProvider();

        try {
            // Exercise AlgorithmParameterGenerator.getInstance().
            generateAlgorithmParameters();

            // 1. Create a self-signed X.509 certificate.
            X509Certificate createdCertificate =
                    createSelfSignedCertificate();

            // 2. Save the certificate.
            saveCertificate(createdCertificate);

            // 3. Load the certificate.
            X509Certificate loadedCertificate =
                    loadCertificate();

            // 4. Use and validate the certificate.
            useCertificate(loadedCertificate);

        } catch (Exception exception) {
            System.err.println("Application failed:");
            exception.printStackTrace();
        }

        // PQC / KeyPairGenerator cases (formerly JUnit tests).
        System.out.println();
        System.out.println("=== PQC key generation cases ===");

        runCase("generateMlKemKeyPair", App::generateMlKemKeyPair);
        runCase("generateMlDsaKeyPair", App::generateMlDsaKeyPair);
        runCase("controlSingleArgument", App::controlSingleArgument);
        runCase("controlLiteralProvider", App::controlLiteralProvider);
        runCase("controlProviderConstant", App::controlProviderConstant);
        runCase("controlLocalProviderConstant",
                App::controlLocalProviderConstant);
        runCase("controlProviderConstantAES",
                App::controlProviderConstantAES);
        runCase("mlDsaExplicitProviderDetection",
                App::mlDsaExplicitProviderDetection);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static void registerBouncyCastleProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** Runs one case, reports PASS / FAIL, and never stops the others. */
    private static void runCase(String name, CheckedRunnable action) {
        try {
            action.run();
            System.out.println("[PASS] " + name);
        } catch (Throwable t) {
            System.out.println("[FAIL] " + name + " -> " + t);
            t.printStackTrace(System.out);
        }
    }

    private static void assertNotNull(Object value) {
        if (value == null) {
            throw new IllegalStateException("Expected non-null value");
        }
    }

    private static void assertTrue(boolean condition) {
        if (!condition) {
            throw new IllegalStateException("Expected condition to be true");
        }
    }

    private static void assertKeyPairNotNull(KeyPair keyPair) {
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
    }

    // ------------------------------------------------------------------
    // PQC / KeyPairGenerator cases
    // ------------------------------------------------------------------

    private static void generateMlKemKeyPair() throws Exception {
        KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("ML-KEM");

        KeyPair kp = kpg.generateKeyPair();

        assertKeyPairNotNull(kp);
    }

    private static void generateMlDsaKeyPair() throws Exception {
        KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("ML-DSA");

        KeyPair kp = kpg.generateKeyPair();

        assertKeyPairNotNull(kp);
    }

    private static void controlSingleArgument() throws Exception {
        KeyPairGenerator generator =
                KeyPairGenerator.getInstance("ML-DSA");

        KeyPair keyPair = generator.generateKeyPair();

        assertKeyPairNotNull(keyPair);
    }

    private static void controlLiteralProvider() throws Exception {
        registerBouncyCastleProvider();

        KeyPairGenerator generator =
                KeyPairGenerator.getInstance("ML-DSA", "BC");

        KeyPair keyPair = generator.generateKeyPair();

        assertKeyPairNotNull(keyPair);
    }

    private static void controlProviderConstant() throws Exception {
        registerBouncyCastleProvider();

        System.out.println(
                "Bouncy Castle provider name: "
                        + BouncyCastleProvider.PROVIDER_NAME);

        KeyPairGenerator generator = KeyPairGenerator.getInstance(
                "ML-DSA", BouncyCastleProvider.PROVIDER_NAME);

        KeyPair keyPair = generator.generateKeyPair();

        assertKeyPairNotNull(keyPair);
    }

    private static void controlLocalProviderConstant() throws Exception {
        registerBouncyCastleProvider();

        KeyPairGenerator generator = KeyPairGenerator.getInstance(
                "ML-DSA", LOCAL_PROVIDER_NAME);

        KeyPair keyPair = generator.generateKeyPair();

        assertKeyPairNotNull(keyPair);
    }

    private static void controlProviderConstantAES() throws Exception {
        registerBouncyCastleProvider();

        System.out.println(
                "Bouncy Castle provider name: "
                        + BouncyCastleProvider.PROVIDER_NAME);

        // NOTE: AES is a symmetric algorithm (KeyGenerator), so this
        // KeyPairGenerator lookup is expected to throw
        // NoSuchAlgorithmException. It is kept as a negative control.
        KeyPairGenerator generator = KeyPairGenerator.getInstance(
                "AES", BouncyCastleProvider.PROVIDER_NAME);

        KeyPair keyPair = generator.generateKeyPair();

        assertKeyPairNotNull(keyPair);
    }

    private static void mlDsaExplicitProviderDetection() throws Exception {
        registerBouncyCastleProvider();

        byte[] message = "hello".getBytes(StandardCharsets.UTF_8);

        // Two-argument getInstance(algorithm, provider) call.
        KeyPairGenerator generator = KeyPairGenerator.getInstance(
                "ML-DSA", BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(MLDSAParameterSpec.ml_dsa_65);

        KeyPair keyPair = generator.generateKeyPair();

        assertKeyPairNotNull(keyPair);

        // Two-argument getInstance(algorithm, provider) call.
        Signature signer = Signature.getInstance(
                "ML-DSA", BouncyCastleProvider.PROVIDER_NAME);
        signer.initSign(keyPair.getPrivate());
        signer.update(message);
        byte[] signatureBytes = signer.sign();

        assertNotNull(signatureBytes);

        // Two-argument getInstance(algorithm, provider) call.
        Signature verifier = Signature.getInstance(
                "ML-DSA", BouncyCastleProvider.PROVIDER_NAME);
        verifier.initVerify(keyPair.getPublic());
        verifier.update(message);

        assertTrue(verifier.verify(signatureBytes));
    }

    // ------------------------------------------------------------------
    // Certificate / DH parameter functions (original code)
    // ------------------------------------------------------------------

    private static void generateAlgorithmParameters()
            throws Exception {

        AlgorithmParameterGenerator parameterGenerator =
                AlgorithmParameterGenerator.getInstance(
                        "DiffieHellman"
                );

        parameterGenerator.init(2048);

        AlgorithmParameters algorithmParameters =
                parameterGenerator.generateParameters();

        DHParameterSpec parameterSpec =
                algorithmParameters.getParameterSpec(
                        DHParameterSpec.class
                );

        System.out.println(
                "Algorithm parameters generated successfully"
        );

        System.out.println(
                "Algorithm: "
                        + algorithmParameters.getAlgorithm()
        );

        System.out.println(
                "Prime size: "
                        + parameterSpec.getP().bitLength()
                        + " bits"
        );

        System.out.println(
                "Generator: "
                        + parameterSpec.getG()
        );
    }

    private static X509Certificate createSelfSignedCertificate()
            throws Exception {

        KeyPairGenerator keyPairGenerator =
                KeyPairGenerator.getInstance("RSA");

        keyPairGenerator.initialize(2048);

        KeyPair keyPair =
                keyPairGenerator.generateKeyPair();

        Instant now = Instant.now();

        Date validFrom = Date.from(
                now.minus(1, ChronoUnit.MINUTES)
        );

        Date validUntil = Date.from(
                now.plus(365, ChronoUnit.DAYS)
        );

        BigInteger serialNumber =
                new BigInteger(
                        128,
                        new SecureRandom()
                ).abs();

        X500Name certificateOwner = new X500Name(
                "CN=Test Certificate,"
                        + "OU=Development,"
                        + "O=Example,"
                        + "C=IN"
        );

        JcaX509v3CertificateBuilder certificateBuilder =
                new JcaX509v3CertificateBuilder(
                        certificateOwner,
                        serialNumber,
                        validFrom,
                        validUntil,
                        certificateOwner,
                        keyPair.getPublic()
                );

        ContentSigner contentSigner =
                new JcaContentSignerBuilder(
                        "SHA256withRSA"
                )
                        .setProvider("BC")
                        .build(keyPair.getPrivate());

        X509CertificateHolder certificateHolder =
                certificateBuilder.build(contentSigner);

        X509Certificate certificate =
                new JcaX509CertificateConverter()
                        .setProvider("BC")
                        .getCertificate(certificateHolder);

        System.out.println(
                "1. Self-signed certificate created"
        );

        return certificate;
    }

    private static void saveCertificate(
            X509Certificate certificate
    ) throws Exception {

        Files.createDirectories(
                CERTIFICATE_DIRECTORY
        );

        String pemCertificate =
                convertToPem(certificate.getEncoded());

        Files.writeString(
                CERTIFICATE_PATH,
                pemCertificate,
                StandardCharsets.US_ASCII
        );

        System.out.println(
                "2. Certificate saved to: "
                        + CERTIFICATE_PATH.toAbsolutePath()
        );
    }

    private static X509Certificate loadCertificate()
            throws Exception {

        try (InputStream inputStream =
                     Files.newInputStream(CERTIFICATE_PATH)) {

            CertificateFactory certificateFactory =
                    CertificateFactory.getInstance("X.509");

            X509Certificate certificate =
                    (X509Certificate) certificateFactory
                            .generateCertificate(inputStream);

            System.out.println(
                    "3. Certificate loaded from directory"
            );

            return certificate;
        }
    }

    private static void useCertificate(
            X509Certificate certificate
    ) throws Exception {

        // Check whether the certificate is currently valid.
        certificate.checkValidity();

        // Verify that the certificate is self-signed.
        certificate.verify(certificate.getPublicKey());

        System.out.println(
                "4. Certificate used and validated successfully"
        );

        System.out.println();
        System.out.println("Certificate information");
        System.out.println("-----------------------");

        System.out.println(
                "Subject: "
                        + certificate.getSubjectX500Principal()
        );

        System.out.println(
                "Issuer: "
                        + certificate.getIssuerX500Principal()
        );

        System.out.println(
                "Serial number: "
                        + certificate.getSerialNumber()
        );

        System.out.println(
                "Valid from: "
                        + certificate.getNotBefore()
        );

        System.out.println(
                "Valid until: "
                        + certificate.getNotAfter()
        );

        System.out.println(
                "Signature algorithm: "
                        + certificate.getSigAlgName()
        );

        System.out.println(
                "Public-key algorithm: "
                        + certificate
                                .getPublicKey()
                                .getAlgorithm()
        );
    }

    private static String convertToPem(
            byte[] encodedCertificate
    ) {
        String base64Certificate =
                Base64.getMimeEncoder(
                        64,
                        "\n".getBytes(
                                StandardCharsets.US_ASCII
                        )
                ).encodeToString(encodedCertificate);

        return "-----BEGIN CERTIFICATE-----\n"
                + base64Certificate
                + "\n-----END CERTIFICATE-----\n";
    }
}