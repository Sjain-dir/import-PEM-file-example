package com.example;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
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

    public static void main(String[] args) {
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
}

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