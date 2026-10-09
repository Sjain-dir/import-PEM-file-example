package com.example;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class App {

    // Hard-coded PEM certificate location
    private static final Path CERTIFICATE_PATH =
            Paths.get("certificates", "certificate.pem");

    public static void main(String[] args) {
        try (InputStream inputStream =
                     Files.newInputStream(CERTIFICATE_PATH)) {

            CertificateFactory certificateFactory =
                    CertificateFactory.getInstance("X.509");

            X509Certificate certificate =
                    (X509Certificate) certificateFactory
                            .generateCertificate(inputStream);

            System.out.println("Certificate loaded successfully");
            System.out.println("Subject: "
                    + certificate.getSubjectX500Principal());
            System.out.println("Issuer: "
                    + certificate.getIssuerX500Principal());
            System.out.println("Serial number: "
                    + certificate.getSerialNumber());
            System.out.println("Valid from: "
                    + certificate.getNotBefore());
            System.out.println("Valid until: "
                    + certificate.getNotAfter());
            System.out.println("Signature algorithm: "
                    + certificate.getSigAlgName());
            System.out.println("Public key algorithm: "
                    + certificate.getPublicKey().getAlgorithm());

            System.out.println("\nComplete certificate:");
            System.out.println(certificate);

        } catch (Exception exception) {
            System.err.println(
                    "Failed to load certificate from: "
                            + CERTIFICATE_PATH.toAbsolutePath()
            );
            exception.printStackTrace();
        }
    }
}