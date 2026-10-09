package com.example;

import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
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
        for (int i = 0; i<=2 ; i++) {

                try {
                    // 1. Create the certificate.
                    X509Certificate createdCertificate =
                            createSelfSignedCertificate();
        
                    // 2. Save the certificate in the directory.
                    saveCertificate(createdCertificate);
        
                    // 3. Pick up the certificate from the directory.
                    X509Certificate loadedCertificate =
                            loadCertificate();
        
                    // 4. Use and validate the loaded certificate.
                    useCertificate(loadedCertificate);
        
                } catch (Exception exception) {
                    System.err.println("Application failed:");
                    exception.printStackTrace();
                }
        }
    }

    private static X509Certificate createSelfSignedCertificate()
            throws Exception {

        /*
         * A certificate must contain a public key and must be signed.
         * Therefore, an RSA key pair is generated as part of certificate
         * creation. It is not saved to disk.
         */
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

        CertificateValidity validity =
                new CertificateValidity(validFrom, validUntil);

        BigInteger serialNumber =
                new BigInteger(
                        128,
                        new SecureRandom()
                ).abs();

        X500Name certificateOwner = new X500Name(
                "CN=Test Certificate,"
                        + " OU=Development,"
                        + " O=Example,"
                        + " C=IN"
        );

        X509CertInfo certificateInfo =
                new X509CertInfo();

        certificateInfo.setVersion(
                new CertificateVersion(
                        CertificateVersion.V3
                )
        );

        certificateInfo.setSerialNumber(
                new CertificateSerialNumber(
                        serialNumber
                )
        );

        certificateInfo.setSubject(
                certificateOwner
        );

        certificateInfo.setIssuer(
                certificateOwner
        );

        certificateInfo.setValidity(
                validity
        );

        certificateInfo.setKey(
                new CertificateX509Key(
                        keyPair.getPublic()
                )
        );

        X509Certificate certificate =
                X509CertImpl.newSigned(
                        certificateInfo,
                        keyPair.getPrivate(),
                        "SHA256withRSA"
                );

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

        String pemCertificate = convertToPem(
                certificate.getEncoded()
        );

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
        certificate.verify(
                certificate.getPublicKey()
        );

        System.out.println(
                "4. Certificate validated successfully"
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