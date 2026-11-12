package com.example;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.NullCipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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

        // Intentionally insecure fixtures for crypto-posture scanners.
        System.out.println();
        System.out.println("=== Intentional violation fixtures ===");
        runViolationFixtures();
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

    // ==================================================================
    // INTENTIONAL VIOLATION FIXTURES
    //
    // Everything below is deliberately insecure. It exists only so a
    // crypto-posture / CBOM scanner has something to flag. Do not copy.
    //
    // REAL      = the weakness is visible in plain JCA / Bouncy Castle code.
    // SIMULATED = the weakness lives in a KMS / cloud control plane
    //             (rotation, purge state, accounts, IAM...). JCA has no
    //             API for it, so it is modelled with the in-code KeyRecord
    //             metadata below. A scanner only sees it if it reads
    //             that metadata.
    // ==================================================================

    private static final Path VIOLATION_DIRECTORY =
            CERTIFICATE_DIRECTORY.resolve("violations");

    private static final byte[] SERVICE_PAYLOAD =
            "customer-record: account=12345"
                    .getBytes(StandardCharsets.UTF_8);

    /** Weak, well-known keystore password. */
    private static final char[] WEAK_PASSWORD = "changeit".toCharArray();

    /** Hard-coded key material that is never rotated. */
    private static final byte[] HARDCODED_AES_KEY =
            "0123456789abcdef".getBytes(StandardCharsets.US_ASCII);

    private static final List<KeyRecord> KEY_INVENTORY = new ArrayList<>();

    /** In-code stand-in for KMS key metadata (SIMULATED findings). */
    private static final class KeyRecord {
        final String alias;
        final Key key;
        final String algorithm;
        final int bits;
        String origin = "CUSTOMER_IMPORTED";
        String ownerAccount = "111111111111";
        String callerAccount = "111111111111";
        String state = "ENABLED";
        boolean rotationEnabled = true;
        boolean exportable = false;
        Instant createdAt = Instant.now();
        Instant expiresAt = Instant.now().plus(365, ChronoUnit.DAYS);
        Instant lastUsedAt = Instant.now();
        List<String> usages = new ArrayList<>(List.of("ENCRYPT", "DECRYPT"));
        List<String> managers = new ArrayList<>(List.of("kms-admin"));

        KeyRecord(String alias, Key key, String algorithm, int bits) {
            this.alias = alias;
            this.key = key;
            this.algorithm = algorithm;
            this.bits = bits;
        }

        KeyRecord origin(String v) { origin = v; return this; }
        KeyRecord owner(String v) { ownerAccount = v; return this; }
        KeyRecord caller(String v) { callerAccount = v; return this; }
        KeyRecord state(String v) { state = v; return this; }
        KeyRecord noRotation() { rotationEnabled = false; return this; }
        KeyRecord exportable() { exportable = true; return this; }
        KeyRecord noExpiry() { expiresAt = null; return this; }
        KeyRecord neverUsed() { lastUsedAt = null; return this; }
        KeyRecord createdDaysAgo(long d) {
            createdAt = Instant.now().minus(d, ChronoUnit.DAYS);
            return this;
        }
        KeyRecord expiredDaysAgo(long d) {
            expiresAt = Instant.now().minus(d, ChronoUnit.DAYS);
            return this;
        }
        KeyRecord lastUsedDaysAgo(long d) {
            lastUsedAt = Instant.now().minus(d, ChronoUnit.DAYS);
            return this;
        }
        KeyRecord usages(String... v) {
            usages = new ArrayList<>(List.of(v));
            return this;
        }
        KeyRecord managers(String... v) {
            managers = new ArrayList<>(List.of(v));
            return this;
        }
    }

    private static KeyRecord register(KeyRecord record) {
        KEY_INVENTORY.add(record);
        return record;
    }

    private static void runViolationFixtures() {
        expiredCertificates();                       // expired_certificate
        keysWithoutExpiry();                         // keys_without_expiry
        nonCompliantCertificateBySignatureAlgorithm();
        nonCompliantCertificateByKeyAlgorithm();
        quantumVulnerableCertificates();
        overlyPermissiveCertificateUsage();
        overlyPermissiveKeyUsage();
        nonCompliantKeys();
        quantumVulnerableKeys();
        exportableKeys();
        unencryptedServices();
        servicesEncryptedWithNonCompliantKey();
        servicesEncryptedWithQuantumVulnerableKey();
        servicesEncryptedWithExpiredKey();
        servicesEncryptedWithExportableKey();
        sharedKeys();
        servicesEncryptedWithSharedKey();
        sharedCertificates();
        servicesEncryptedWithOverlyPermissiveUsageKey();
        overlyPermissiveKeyManagement();
        servicesEncryptedWithOverlyPermissiveManagementKey();
        keysWithRotationDisabled();
        unusedKeys();
        expiredKeys();
        servicesEncryptedWithPurgedKey();
        servicesEncryptedWithSoftDeletedKey();
        cspGeneratedKeys();
        servicesEncryptedWithCspGeneratedKey();
        servicesEncryptedWithPlatformManagedKey();
        crossAccountKeys();
        servicesEncryptedWithCrossAccountKey();
        printKeyInventory();
    }

    // ------------------------------------------------------------------
    // Fixture helpers
    // ------------------------------------------------------------------

    private static Date daysFromNow(long days) {
        return Date.from(Instant.now().plus(days, ChronoUnit.DAYS));
    }

    private static String dn(String commonName) {
        return "CN=" + commonName + ",OU=Development,O=Example,C=IN";
    }

    private static KeyPair genRsa(int bits) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(bits);
        return generator.generateKeyPair();
    }

    private static KeyPair genDsa(int bits) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA");
        generator.initialize(bits);
        return generator.generateKeyPair();
    }

    /** EC key pair from Bouncy Castle (also supports legacy curves). */
    private static KeyPair genEc(String curve) throws Exception {
        KeyPairGenerator generator =
                KeyPairGenerator.getInstance("EC", "BC");
        generator.initialize(new ECGenParameterSpec(curve));
        return generator.generateKeyPair();
    }

    /** bits == 0 keeps the algorithm's default key size. */
    private static SecretKey genSecret(String algorithm, int bits)
            throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance(algorithm);
        if (bits > 0) {
            generator.init(bits);
        }
        return generator.generateKey();
    }

    /** Certificate with a plain digitalSignature key usage. */
    private static X509Certificate issue(String commonName, KeyPair keyPair,
            String signatureAlgorithm, Date from, Date until)
            throws Exception {
        return issueCertificate(dn(commonName), keyPair, signatureAlgorithm,
                from, until, false,
                new KeyUsage(KeyUsage.digitalSignature), null);
    }

    private static X509Certificate issueCertificate(String subject,
            KeyPair keyPair, String signatureAlgorithm, Date from,
            Date until, boolean isCa, KeyUsage keyUsage,
            ExtendedKeyUsage extendedKeyUsage) throws Exception {

        X500Name name = new X500Name(subject);

        JcaX509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(
                        name,
                        new BigInteger(128, new SecureRandom()).abs(),
                        from,
                        until,
                        name,
                        keyPair.getPublic());

        builder.addExtension(Extension.basicConstraints, true,
                new BasicConstraints(isCa));
        if (keyUsage != null) {
            builder.addExtension(Extension.keyUsage, true, keyUsage);
        }
        if (extendedKeyUsage != null) {
            builder.addExtension(Extension.extendedKeyUsage, false,
                    extendedKeyUsage);
        }

        ContentSigner signer =
                new JcaContentSignerBuilder(signatureAlgorithm)
                        .setProvider("BC")
                        .build(keyPair.getPrivate());

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(builder.build(signer));
    }

    private static void reportCertificate(String finding,
            X509Certificate certificate) {
        System.out.println("   [" + finding + "] subject="
                + certificate.getSubjectX500Principal()
                + " sig=" + certificate.getSigAlgName()
                + " key=" + certificate.getPublicKey().getAlgorithm()
                + " notAfter=" + certificate.getNotAfter());
    }

    private static void reportKey(String finding, String label, Key key) {
        System.out.println("   [" + finding + "] " + label
                + " algorithm=" + key.getAlgorithm()
                + " format=" + key.getFormat());
    }

    /** A "service" that encrypts SERVICE_PAYLOAD with the given key. */
    private static byte[] serviceEncrypt(String service,
            String transformation, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(SERVICE_PAYLOAD);
        System.out.println("   [service:" + service + "] "
                + transformation + " -> " + encrypted.length + " bytes");
        return encrypted;
    }

    private static byte[] serviceEncrypt(String service, KeyRecord record,
            String transformation) throws Exception {
        System.out.println("   [service:" + service + "] key=" + record.alias
                + " state=" + record.state
                + " owner=" + record.ownerAccount
                + " caller=" + record.callerAccount
                + " origin=" + record.origin);
        return serviceEncrypt(service, transformation, record.key);
    }

    private static void writeFile(String name, byte[] content)
            throws Exception {
        Files.createDirectories(VIOLATION_DIRECTORY);
        Files.write(VIOLATION_DIRECTORY.resolve(name), content);
    }

    private static void printKeyInventory() {
        System.out.println();
        System.out.println("=== Simulated key inventory (KeyRecord) ===");
        for (KeyRecord r : KEY_INVENTORY) {
            System.out.println(r.alias + " | " + r.algorithm + "-" + r.bits
                    + " | state=" + r.state
                    + " | origin=" + r.origin
                    + " | owner=" + r.ownerAccount
                    + " | caller=" + r.callerAccount
                    + " | rotation=" + r.rotationEnabled
                    + " | exportable=" + r.exportable
                    + " | created=" + r.createdAt
                    + " | expires=" + r.expiresAt
                    + " | lastUsed=" + r.lastUsedAt
                    + " | usages=" + r.usages
                    + " | managers=" + r.managers);
        }
    }

    // ------------------------------------------------------------------
    // Certificates
    // ------------------------------------------------------------------

    // expired_certificate (critical) - REAL
    private static void expiredCertificates() {
        runCase("expired_certificate#1 RSA-2048 expired 400 days ago", () ->
                reportCertificate("expired_certificate",
                        issue("expired-rsa", genRsa(2048), "SHA256withRSA",
                                daysFromNow(-800), daysFromNow(-400))));

        runCase("expired_certificate#2 EC P-256 expired 30 days ago", () ->
                reportCertificate("expired_certificate",
                        issue("expired-ec", genEc("secp256r1"),
                                "SHA256withECDSA",
                                daysFromNow(-365), daysFromNow(-30))));

        runCase("expired_certificate#3 RSA-3072 expired 1 hour ago", () ->
                reportCertificate("expired_certificate",
                        issue("expired-rsa-3072", genRsa(3072),
                                "SHA256withRSA",
                                daysFromNow(-365),
                                Date.from(Instant.now()
                                        .minus(1, ChronoUnit.HOURS)))));
    }

    // keys_without_expiry (high) - REAL for certificates, SIMULATED for #4
    private static void keysWithoutExpiry() {
        runCase("keys_without_expiry#1 cert valid until 9999-12-31", () ->
                reportCertificate("keys_without_expiry",
                        issue("no-expiry-9999", genRsa(2048),
                                "SHA256withRSA", daysFromNow(-1),
                                Date.from(ZonedDateTime
                                        .of(9999, 12, 31, 23, 59, 59, 0,
                                                ZoneOffset.UTC)
                                        .toInstant()))));

        runCase("keys_without_expiry#2 cert valid for 100 years", () ->
                reportCertificate("keys_without_expiry",
                        issue("no-expiry-100y", genRsa(2048),
                                "SHA256withRSA", daysFromNow(-1),
                                daysFromNow(36500))));

        runCase("keys_without_expiry#3 EC cert valid for 50 years", () ->
                reportCertificate("keys_without_expiry",
                        issue("no-expiry-50y", genEc("secp256r1"),
                                "SHA256withECDSA", daysFromNow(-1),
                                daysFromNow(18250))));

        runCase("keys_without_expiry#4 AES key record with no expiry", () ->
                register(new KeyRecord("alias/no-expiry-aes",
                        genSecret("AES", 256), "AES", 256).noExpiry()));
    }

    // non_compliant_certificate_by_signature_algorithm (high) - REAL
    private static void nonCompliantCertificateBySignatureAlgorithm() {
        runCase("cert_signature#1 MD5withRSA", () ->
                reportCertificate("non_compliant_certificate_by_signature_algorithm",
                        issue("sig-md5-rsa", genRsa(2048), "MD5withRSA",
                                daysFromNow(-1), daysFromNow(365))));

        runCase("cert_signature#2 SHA1withRSA", () ->
                reportCertificate("non_compliant_certificate_by_signature_algorithm",
                        issue("sig-sha1-rsa", genRsa(2048), "SHA1withRSA",
                                daysFromNow(-1), daysFromNow(365))));

        runCase("cert_signature#3 SHA1withECDSA", () ->
                reportCertificate("non_compliant_certificate_by_signature_algorithm",
                        issue("sig-sha1-ecdsa", genEc("secp256r1"),
                                "SHA1withECDSA",
                                daysFromNow(-1), daysFromNow(365))));
    }

    // non_compliant_certificate_by_key_algorithm (critical) - REAL
    private static void nonCompliantCertificateByKeyAlgorithm() {
        runCase("cert_key_algorithm#1 RSA-1024", () ->
                reportCertificate("non_compliant_certificate_by_key_algorithm",
                        issue("weak-rsa-1024", genRsa(1024), "SHA256withRSA",
                                daysFromNow(-1), daysFromNow(365))));

        runCase("cert_key_algorithm#2 DSA-1024", () ->
                reportCertificate("non_compliant_certificate_by_key_algorithm",
                        issue("weak-dsa-1024", genDsa(1024), "SHA1withDSA",
                                daysFromNow(-1), daysFromNow(365))));

        runCase("cert_key_algorithm#3 EC secp192r1", () ->
                reportCertificate("non_compliant_certificate_by_key_algorithm",
                        issue("weak-ec-192", genEc("secp192r1"),
                                "SHA256withECDSA",
                                daysFromNow(-1), daysFromNow(365))));
    }

    // quantum_vulnerable_certificates (low) - REAL
    private static void quantumVulnerableCertificates() {
        runCase("quantum_cert#1 RSA-2048 certificate", () ->
                reportCertificate("quantum_vulnerable_certificates",
                        issue("pq-rsa-2048", genRsa(2048), "SHA256withRSA",
                                daysFromNow(-1), daysFromNow(365))));

        runCase("quantum_cert#2 EC P-256 certificate", () ->
                reportCertificate("quantum_vulnerable_certificates",
                        issue("pq-ec-256", genEc("secp256r1"),
                                "SHA256withECDSA",
                                daysFromNow(-1), daysFromNow(365))));

        runCase("quantum_cert#3 EC P-384 certificate", () ->
                reportCertificate("quantum_vulnerable_certificates",
                        issue("pq-ec-384", genEc("secp384r1"),
                                "SHA384withECDSA",
                                daysFromNow(-1), daysFromNow(365))));
    }

    // overly_permissive_certificate_usage (high) - REAL
    private static void overlyPermissiveCertificateUsage() {
        runCase("cert_usage#1 leaf certificate with CA:true", () ->
                reportCertificate("overly_permissive_certificate_usage",
                        issueCertificate(dn("leaf-that-is-a-ca"),
                                genRsa(2048), "SHA256withRSA",
                                daysFromNow(-1), daysFromNow(365), true,
                                new KeyUsage(KeyUsage.digitalSignature),
                                null)));

        runCase("cert_usage#2 anyExtendedKeyUsage", () ->
                reportCertificate("overly_permissive_certificate_usage",
                        issueCertificate(dn("any-eku"),
                                genRsa(2048), "SHA256withRSA",
                                daysFromNow(-1), daysFromNow(365), false,
                                new KeyUsage(KeyUsage.digitalSignature),
                                new ExtendedKeyUsage(
                                        KeyPurposeId.anyExtendedKeyUsage))));

        runCase("cert_usage#3 server+client+code+email+time+OCSP EKU", () ->
                reportCertificate("overly_permissive_certificate_usage",
                        issueCertificate(dn("every-eku"),
                                genRsa(2048), "SHA256withRSA",
                                daysFromNow(-1), daysFromNow(365), false,
                                new KeyUsage(KeyUsage.digitalSignature),
                                new ExtendedKeyUsage(new KeyPurposeId[] {
                                        KeyPurposeId.id_kp_serverAuth,
                                        KeyPurposeId.id_kp_clientAuth,
                                        KeyPurposeId.id_kp_codeSigning,
                                        KeyPurposeId.id_kp_emailProtection,
                                        KeyPurposeId.id_kp_timeStamping,
                                        KeyPurposeId.id_kp_OCSPSigning }))));
    }

    // ------------------------------------------------------------------
    // Keys: usage, strength, quantum, export
    // ------------------------------------------------------------------

    // overly_permissive_key_usage (high) - REAL (#1, #2), SIMULATED (#3)
    private static void overlyPermissiveKeyUsage() {
        runCase("key_usage#1 one RSA key signs, encrypts and wraps", () -> {
            KeyPair keyPair = genRsa(2048);

            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(keyPair.getPrivate());
            signer.update(SERVICE_PAYLOAD);
            signer.sign();

            Cipher encrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            encrypt.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            encrypt.doFinal(SERVICE_PAYLOAD);

            Cipher wrap = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            wrap.init(Cipher.WRAP_MODE, keyPair.getPublic());
            wrap.wrap(genSecret("AES", 128));

            reportKey("overly_permissive_key_usage",
                    "RSA-2048 used for sign+encrypt+wrap",
                    keyPair.getPublic());
        });

        runCase("key_usage#2 certificate with every KeyUsage bit set", () ->
                reportCertificate("overly_permissive_key_usage",
                        issueCertificate(dn("all-key-usages"),
                                genRsa(2048), "SHA256withRSA",
                                daysFromNow(-1), daysFromNow(365), false,
                                allKeyUsages(), null)));

        runCase("key_usage#3 key record allowed every operation", () ->
                register(new KeyRecord("alias/all-usages-aes",
                        genSecret("AES", 256), "AES", 256)
                        .usages("ENCRYPT", "DECRYPT", "SIGN", "VERIFY",
                                "WRAP", "UNWRAP", "DERIVE", "MAC")));
    }

    private static KeyUsage allKeyUsages() {
        return new KeyUsage(KeyUsage.digitalSignature
                | KeyUsage.nonRepudiation
                | KeyUsage.keyEncipherment
                | KeyUsage.dataEncipherment
                | KeyUsage.keyAgreement
                | KeyUsage.keyCertSign
                | KeyUsage.cRLSign
                | KeyUsage.encipherOnly
                | KeyUsage.decipherOnly);
    }

    // noncompliant_keys (high) - REAL
    private static void nonCompliantKeys() {
        runCase("noncompliant_key#1 RSA-1024", () ->
                reportKey("noncompliant_keys", "RSA-1024",
                        genRsa(1024).getPrivate()));

        runCase("noncompliant_key#2 DES (56-bit)", () ->
                reportKey("noncompliant_keys", "DES-56",
                        genSecret("DES", 0)));

        runCase("noncompliant_key#3 RC4 (ARCFOUR) 128-bit", () ->
                reportKey("noncompliant_keys", "RC4-128",
                        genSecret("ARCFOUR", 128)));

        runCase("noncompliant_key#4 EC secp192r1", () ->
                reportKey("noncompliant_keys", "EC-192",
                        genEc("secp192r1").getPrivate()));

        runCase("noncompliant_key#5 DSA-1024", () ->
                reportKey("noncompliant_keys", "DSA-1024",
                        genDsa(1024).getPrivate()));
    }

    // quantum_vulnerable_keys (low) - REAL
    private static void quantumVulnerableKeys() {
        runCase("quantum_key#1 RSA-3072", () ->
                reportKey("quantum_vulnerable_keys", "RSA-3072",
                        genRsa(3072).getPrivate()));

        runCase("quantum_key#2 EC P-521", () ->
                reportKey("quantum_vulnerable_keys", "EC-521",
                        genEc("secp521r1").getPrivate()));

        runCase("quantum_key#3 finite-field DH-2048", () -> {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("DH");
            generator.initialize(2048);
            reportKey("quantum_vulnerable_keys", "DH-2048",
                    generator.generateKeyPair().getPrivate());
        });
    }

    // exportable_keys (low) - REAL
    private static void exportableKeys() {
        runCase("exportable_key#1 AES key bytes exported to file", () -> {
            SecretKey secret = genSecret("AES", 256);
            writeFile("exported-aes.key", secret.getEncoded());
            System.out.println("   [exportable_keys] getEncoded() -> "
                    + Base64.getEncoder().encodeToString(secret.getEncoded())
                            .length() + " base64 chars");
        });

        runCase("exportable_key#2 RSA private key as plaintext PKCS#8 PEM", () -> {
            byte[] pkcs8 = genRsa(2048).getPrivate().getEncoded();
            String pem = "-----BEGIN PRIVATE KEY-----\n"
                    + Base64.getMimeEncoder(64, "\n".getBytes(
                            StandardCharsets.US_ASCII)).encodeToString(pkcs8)
                    + "\n-----END PRIVATE KEY-----\n";
            writeFile("exported-rsa-private.pem",
                    pem.getBytes(StandardCharsets.US_ASCII));
        });

        runCase("exportable_key#3 private key in PKCS12 with weak password", () -> {
            KeyPair keyPair = genRsa(2048);
            X509Certificate certificate = issue("exportable-p12", keyPair,
                    "SHA256withRSA", daysFromNow(-1), daysFromNow(365));

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            keyStore.setKeyEntry("exportable", keyPair.getPrivate(),
                    WEAK_PASSWORD, new Certificate[] {certificate});

            Files.createDirectories(VIOLATION_DIRECTORY);
            try (OutputStream out = Files.newOutputStream(
                    VIOLATION_DIRECTORY.resolve("exportable.p12"))) {
                keyStore.store(out, WEAK_PASSWORD);
            }
        });
    }

    // ------------------------------------------------------------------
    // Services using bad crypto
    // ------------------------------------------------------------------

    // unencrypted_services (critical) - REAL
    private static void unencryptedServices() {
        runCase("unencrypted_service#1 NullCipher", () -> {
            Cipher cipher = new NullCipher();
            cipher.init(Cipher.ENCRYPT_MODE, genSecret("AES", 128));
            byte[] out = cipher.doFinal(SERVICE_PAYLOAD);
            System.out.println("   [service:null-cipher-service] output "
                    + "equals plaintext: "
                    + java.util.Arrays.equals(out, SERVICE_PAYLOAD));
        });

        runCase("unencrypted_service#2 payload persisted as plaintext", () ->
                writeFile("plaintext-payload.txt", SERVICE_PAYLOAD));

        runCase("unencrypted_service#3 Base64 used as 'encryption'", () ->
                System.out.println("   [service:base64-service] "
                        + Base64.getEncoder()
                                .encodeToString(SERVICE_PAYLOAD)));
    }

    // services_encrypted_with_noncompliant_key (high) - REAL
    private static void servicesEncryptedWithNonCompliantKey() {
        runCase("svc_noncompliant#1 DES/ECB", () ->
                serviceEncrypt("legacy-des-service",
                        "DES/ECB/PKCS5Padding", genSecret("DES", 0)));

        runCase("svc_noncompliant#2 RC4", () ->
                serviceEncrypt("legacy-rc4-service",
                        "ARCFOUR", genSecret("ARCFOUR", 128)));

        runCase("svc_noncompliant#3 RSA-1024 PKCS#1 v1.5", () ->
                serviceEncrypt("legacy-rsa1024-service",
                        "RSA/ECB/PKCS1Padding", genRsa(1024).getPublic()));
    }

    // services_encrypted_with_quantum_vulnerable_key (low) - REAL
    private static void servicesEncryptedWithQuantumVulnerableKey() {
        runCase("svc_quantum#1 RSA-2048 OAEP", () ->
                serviceEncrypt("rsa-oaep-service",
                        "RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
                        genRsa(2048).getPublic()));

        runCase("svc_quantum#2 RSA-3072 PKCS#1 v1.5", () ->
                serviceEncrypt("rsa-pkcs1-service",
                        "RSA/ECB/PKCS1Padding", genRsa(3072).getPublic()));

        runCase("svc_quantum#3 ECDH P-256 derived AES-GCM", () -> {
            KeyPair alice = genEc("secp256r1");
            KeyPair bob = genEc("secp256r1");

            KeyAgreement agreement = KeyAgreement.getInstance("ECDH", "BC");
            agreement.init(alice.getPrivate());
            agreement.doPhase(bob.getPublic(), true);

            SecretKey derived = new SecretKeySpec(
                    MessageDigest.getInstance("SHA-256")
                            .digest(agreement.generateSecret()),
                    "AES");
            serviceEncrypt("ecdh-service", "AES/GCM/NoPadding", derived);
        });
    }

    // services_encrypted_with_expired_key (low) - REAL (#1, #2), SIMULATED (#3)
    private static void servicesEncryptedWithExpiredKey() {
        runCase("svc_expired#1 RSA public key from cert expired 90d ago", () ->
                serviceEncrypt("expired-cert-service-a",
                        "RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
                        issue("svc-expired-a", genRsa(2048), "SHA256withRSA",
                                daysFromNow(-500), daysFromNow(-90))
                                .getPublicKey()));

        runCase("svc_expired#2 RSA public key from cert expired yesterday", () ->
                serviceEncrypt("expired-cert-service-b",
                        "RSA/ECB/PKCS1Padding",
                        issue("svc-expired-b", genRsa(2048), "SHA256withRSA",
                                daysFromNow(-365), daysFromNow(-1))
                                .getPublicKey()));

        runCase("svc_expired#3 AES key record expired 10 days ago", () ->
                serviceEncrypt("expired-aes-service",
                        register(new KeyRecord("alias/expired-aes",
                                genSecret("AES", 256), "AES", 256)
                                .expiredDaysAgo(10)),
                        "AES/GCM/NoPadding"));
    }

    // services_encrypted_with_exportable_key (low) - REAL
    private static void servicesEncryptedWithExportableKey() {
        runCase("svc_exportable#1 key rebuilt from exported raw bytes", () -> {
            byte[] raw = genSecret("AES", 256).getEncoded();
            serviceEncrypt("raw-bytes-service", "AES/GCM/NoPadding",
                    new SecretKeySpec(raw, "AES"));
        });

        runCase("svc_exportable#2 key loaded from PKCS12 SecretKeyEntry", () -> {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            keyStore.setEntry("svc-key",
                    new KeyStore.SecretKeyEntry(genSecret("AES", 256)),
                    new KeyStore.PasswordProtection(WEAK_PASSWORD));
            serviceEncrypt("keystore-service", "AES/GCM/NoPadding",
                    keyStore.getKey("svc-key", WEAK_PASSWORD));
        });

        runCase("svc_exportable#3 key decoded from Base64 config value", () -> {
            String fromConfig = Base64.getEncoder()
                    .encodeToString(genSecret("AES", 128).getEncoded());
            serviceEncrypt("config-key-service", "AES/CBC/PKCS5Padding",
                    new SecretKeySpec(
                            Base64.getDecoder().decode(fromConfig), "AES"));
        });
    }

    // ------------------------------------------------------------------
    // Shared keys / certificates
    // ------------------------------------------------------------------

    // shared_keys (high) - REAL
    private static void sharedKeys() {
        runCase("shared_key#1 one AES key under three tenant aliases", () -> {
            SecretKey shared = genSecret("AES", 256);
            for (String tenant : new String[] {"tenant-a", "tenant-b",
                    "tenant-c"}) {
                register(new KeyRecord("alias/" + tenant, shared, "AES", 256));
            }
        });

        runCase("shared_key#2 one RSA pair for signing and encryption", () -> {
            KeyPair keyPair = genRsa(2048);
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(keyPair.getPrivate());
            signer.update(SERVICE_PAYLOAD);
            signer.sign();
            serviceEncrypt("shared-rsa-encrypt-service",
                    "RSA/ECB/PKCS1Padding", keyPair.getPublic());
        });

        runCase("shared_key#3 same AES key in two keystores", () -> {
            SecretKey shared = genSecret("AES", 256);
            for (String store : new String[] {"primary", "disaster-recovery"}) {
                KeyStore keyStore = KeyStore.getInstance("PKCS12");
                keyStore.load(null, null);
                keyStore.setEntry("shared-" + store,
                        new KeyStore.SecretKeyEntry(shared),
                        new KeyStore.PasswordProtection(WEAK_PASSWORD));
                System.out.println("   [shared_keys] stored in " + store);
            }
        });
    }

    // services_encrypted_with_shared_key (high) - REAL
    private static void servicesEncryptedWithSharedKey() {
        runCase("svc_shared#1 payments/logging/backup share one AES key", () -> {
            SecretKey shared = genSecret("AES", 256);
            for (String service : new String[] {"payments-service",
                    "logging-service", "backup-service"}) {
                serviceEncrypt(service, "AES/GCM/NoPadding", shared);
            }
        });

        runCase("svc_shared#2 three services share one RSA public key", () -> {
            PublicKey shared = genRsa(2048).getPublic();
            for (String service : new String[] {"orders-service",
                    "invoices-service", "reports-service"}) {
                serviceEncrypt(service,
                        "RSA/ECB/OAEPWithSHA-256AndMGF1Padding", shared);
            }
        });

        runCase("svc_shared#3 prod and dev share one AES key", () -> {
            SecretKey shared = genSecret("AES", 128);
            for (String environment : new String[] {"prod", "dev"}) {
                serviceEncrypt("app-" + environment, "AES/CBC/PKCS5Padding",
                        shared);
            }
        });
    }

    // shared_certificate (high) - REAL
    private static void sharedCertificates() {
        runCase("shared_cert#1 one certificate in three truststores", () -> {
            X509Certificate shared = issue("shared-cert", genRsa(2048),
                    "SHA256withRSA", daysFromNow(-1), daysFromNow(365));
            for (String store : new String[] {"web", "api", "database"}) {
                KeyStore keyStore = KeyStore.getInstance("PKCS12");
                keyStore.load(null, null);
                keyStore.setCertificateEntry("shared-cert", shared);
                System.out.println("   [shared_certificate] installed in "
                        + store + "-truststore");
            }
        });

        runCase("shared_cert#2 same cert and private key in two keystores", () -> {
            KeyPair keyPair = genRsa(2048);
            X509Certificate shared = issue("shared-identity", keyPair,
                    "SHA256withRSA", daysFromNow(-1), daysFromNow(365));
            for (String alias : new String[] {"server-a", "server-b"}) {
                KeyStore keyStore = KeyStore.getInstance("PKCS12");
                keyStore.load(null, null);
                keyStore.setKeyEntry(alias, keyPair.getPrivate(),
                        WEAK_PASSWORD, new Certificate[] {shared});
                System.out.println("   [shared_certificate] identity used by "
                        + alias);
            }
        });

        runCase("shared_cert#3 one certificate mapped to four services", () -> {
            X509Certificate shared = issue("shared-service-cert",
                    genRsa(2048), "SHA256withRSA",
                    daysFromNow(-1), daysFromNow(365));
            Map<String, X509Certificate> serviceCertificates =
                    new LinkedHashMap<>();
            for (String service : new String[] {"auth", "billing", "search",
                    "notifications"}) {
                serviceCertificates.put(service, shared);
            }
            System.out.println("   [shared_certificate] "
                    + serviceCertificates.keySet() + " use one certificate");
        });
    }

    // services_encrypted_with_overly_permissive_usage_key (high)
    // REAL (#1, #2), SIMULATED (#3)
    private static void servicesEncryptedWithOverlyPermissiveUsageKey() {
        runCase("svc_permissive_usage#1 key from all-KeyUsage cert", () ->
                serviceEncrypt("all-usage-cert-service",
                        "RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
                        issueCertificate(dn("svc-all-usages"), genRsa(2048),
                                "SHA256withRSA", daysFromNow(-1),
                                daysFromNow(365), false, allKeyUsages(),
                                null).getPublicKey()));

        runCase("svc_permissive_usage#2 key from CA:true + anyEKU cert", () ->
                serviceEncrypt("any-eku-cert-service",
                        "RSA/ECB/PKCS1Padding",
                        issueCertificate(dn("svc-any-eku-ca"), genRsa(2048),
                                "SHA256withRSA", daysFromNow(-1),
                                daysFromNow(365), true, allKeyUsages(),
                                new ExtendedKeyUsage(
                                        KeyPurposeId.anyExtendedKeyUsage))
                                .getPublicKey()));

        runCase("svc_permissive_usage#3 AES record with every usage", () ->
                serviceEncrypt("all-usage-aes-service",
                        register(new KeyRecord("alias/svc-all-usages-aes",
                                genSecret("AES", 256), "AES", 256)
                                .usages("ENCRYPT", "DECRYPT", "SIGN",
                                        "VERIFY", "WRAP", "UNWRAP",
                                        "DERIVE", "MAC")),
                        "AES/GCM/NoPadding"));
    }

    // ------------------------------------------------------------------
    // Key management / lifecycle (mostly SIMULATED)
    // ------------------------------------------------------------------

    // overly_permissive_key_management (medium) - SIMULATED
    private static void overlyPermissiveKeyManagement() {
        runCase("key_mgmt#1 wildcard principal can manage key", () ->
                register(new KeyRecord("alias/mgmt-wildcard",
                        genSecret("AES", 256), "AES", 256)
                        .managers("*")));

        runCase("key_mgmt#2 everyone can administer key", () ->
                register(new KeyRecord("alias/mgmt-everyone",
                        genSecret("AES", 256), "AES", 256)
                        .managers("Everyone", "Authenticated-Users")));

        runCase("key_mgmt#3 admin, user and auditor are the same principal", () ->
                register(new KeyRecord("alias/mgmt-no-separation",
                        genRsa(2048).getPublic(), "RSA", 2048)
                        .managers("svc-account", "svc-account",
                                "svc-account")));
    }

    // services_encrypted_with_overly_permissive_management_key (medium)
    // SIMULATED
    private static void servicesEncryptedWithOverlyPermissiveManagementKey() {
        runCase("svc_mgmt#1 key managed by '*'", () ->
                serviceEncrypt("wildcard-managed-service",
                        register(new KeyRecord("alias/svc-mgmt-wildcard",
                                genSecret("AES", 256), "AES", 256)
                                .managers("*")),
                        "AES/GCM/NoPadding"));

        runCase("svc_mgmt#2 key managed by Everyone", () ->
                serviceEncrypt("everyone-managed-service",
                        register(new KeyRecord("alias/svc-mgmt-everyone",
                                genSecret("AES", 128), "AES", 128)
                                .managers("Everyone")),
                        "AES/CBC/PKCS5Padding"));

        runCase("svc_mgmt#3 key managed by any domain user", () ->
                serviceEncrypt("domain-managed-service",
                        register(new KeyRecord("alias/svc-mgmt-domain",
                                genRsa(2048).getPublic(), "RSA", 2048)
                                .managers("domain-users:*")),
                        "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"));
    }

    // keys_with_rotation_disabled (high) - REAL (#1), SIMULATED (#2-#4)
    private static void keysWithRotationDisabled() {
        runCase("rotation_disabled#1 hard-coded static AES key", () ->
                serviceEncrypt("static-key-service", "AES/GCM/NoPadding",
                        new SecretKeySpec(HARDCODED_AES_KEY, "AES")));

        runCase("rotation_disabled#2 AES-256 created 5 years ago", () ->
                register(new KeyRecord("alias/no-rotation-aes",
                        genSecret("AES", 256), "AES", 256)
                        .noRotation().createdDaysAgo(1825)));

        runCase("rotation_disabled#3 RSA-2048 created 3 years ago", () ->
                register(new KeyRecord("alias/no-rotation-rsa",
                        genRsa(2048).getPublic(), "RSA", 2048)
                        .noRotation().createdDaysAgo(1095)));

        runCase("rotation_disabled#4 AES-128 created 2 years ago", () ->
                register(new KeyRecord("alias/no-rotation-aes128",
                        genSecret("AES", 128), "AES", 128)
                        .noRotation().createdDaysAgo(730)));
    }

    // unused_keys (low) - REAL (#1), SIMULATED (#2, #3)
    private static void unusedKeys() {
        runCase("unused_key#1 keystore entries that are never read", () -> {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            for (String alias : new String[] {"unused-1", "unused-2",
                    "unused-3"}) {
                keyStore.setEntry(alias,
                        new KeyStore.SecretKeyEntry(genSecret("AES", 256)),
                        new KeyStore.PasswordProtection(WEAK_PASSWORD));
            }
        });

        runCase("unused_key#2 AES key record never used", () ->
                register(new KeyRecord("alias/never-used-aes",
                        genSecret("AES", 256), "AES", 256).neverUsed()));

        runCase("unused_key#3 RSA key record last used 2 years ago", () ->
                register(new KeyRecord("alias/stale-rsa",
                        genRsa(2048).getPublic(), "RSA", 2048)
                        .lastUsedDaysAgo(730)));
    }

    // expired_keys (critical) - REAL (#1), SIMULATED (#2, #3)
    private static void expiredKeys() {
        runCase("expired_key#1 PKCS12 private key entry with expired cert", () -> {
            KeyPair keyPair = genRsa(2048);
            X509Certificate expired = issue("expired-key-entry", keyPair,
                    "SHA256withRSA", daysFromNow(-730), daysFromNow(-365));

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            keyStore.setKeyEntry("expired-key", keyPair.getPrivate(),
                    WEAK_PASSWORD, new Certificate[] {expired});
        });

        runCase("expired_key#2 AES key record expired 200 days ago", () ->
                register(new KeyRecord("alias/expired-aes-200d",
                        genSecret("AES", 256), "AES", 256)
                        .expiredDaysAgo(200)));

        runCase("expired_key#3 RSA key record expired 1 day ago", () ->
                register(new KeyRecord("alias/expired-rsa-1d",
                        genRsa(2048).getPublic(), "RSA", 2048)
                        .expiredDaysAgo(1)));
    }

    // services_encrypted_with_purged_key (critical)
    // REAL deletion from a KeyStore, SIMULATED state flag
    private static void servicesEncryptedWithPurgedKey() {
        runCase("svc_purged#1 AES-256-GCM key deleted, service keeps using it", () ->
                purgeAndEncrypt("purged-gcm-service", "AES", 256,
                        "AES/GCM/NoPadding"));

        runCase("svc_purged#2 AES-128-CBC key deleted, service keeps using it", () ->
                purgeAndEncrypt("purged-cbc-service", "AES", 128,
                        "AES/CBC/PKCS5Padding"));

        runCase("svc_purged#3 AES-256-CTR key deleted, service keeps using it", () ->
                purgeAndEncrypt("purged-ctr-service", "AES", 256,
                        "AES/CTR/NoPadding"));
    }

    private static void purgeAndEncrypt(String service, String algorithm,
            int bits, String transformation) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);

        SecretKey secret = genSecret(algorithm, bits);
        String alias = "alias/" + service;
        keyStore.setEntry(alias, new KeyStore.SecretKeyEntry(secret),
                new KeyStore.PasswordProtection(WEAK_PASSWORD));

        KeyRecord record = register(
                new KeyRecord(alias, secret, algorithm, bits)
                        .state("PURGED"));

        keyStore.deleteEntry(alias);
        System.out.println("   key '" + alias + "' purged, containsAlias="
                + keyStore.containsAlias(alias));

        serviceEncrypt(service, record, transformation);
    }

    // services_encrypted_with_soft_deleted_key (medium) - SIMULATED
    private static void servicesEncryptedWithSoftDeletedKey() {
        runCase("svc_soft_deleted#1 AES-256 key pending deletion", () ->
                serviceEncrypt("soft-deleted-aes-service",
                        register(new KeyRecord("alias/soft-deleted-aes",
                                genSecret("AES", 256), "AES", 256)
                                .state("SOFT_DELETED")),
                        "AES/GCM/NoPadding"));

        runCase("svc_soft_deleted#2 RSA-2048 key pending deletion", () ->
                serviceEncrypt("soft-deleted-rsa-service",
                        register(new KeyRecord("alias/soft-deleted-rsa",
                                genRsa(2048).getPublic(), "RSA", 2048)
                                .state("SOFT_DELETED")),
                        "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"));

        runCase("svc_soft_deleted#3 AES-128 key pending deletion", () ->
                serviceEncrypt("soft-deleted-cbc-service",
                        register(new KeyRecord("alias/soft-deleted-aes128",
                                genSecret("AES", 128), "AES", 128)
                                .state("SOFT_DELETED")),
                        "AES/CBC/PKCS5Padding"));
    }

    // csp_generated_keys (medium) - provider call is REAL, label SIMULATED
    private static void cspGeneratedKeys() {
        runCase("csp_generated#1 AES from the default provider", () -> {
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(256);
            register(new KeyRecord("alias/csp-aes-default",
                    generator.generateKey(), "AES", 256)
                    .origin("CSP_GENERATED(provider="
                            + generator.getProvider().getName() + ")"));
        });

        runCase("csp_generated#2 AES from Bouncy Castle", () -> {
            KeyGenerator generator = KeyGenerator.getInstance("AES", "BC");
            generator.init(256);
            register(new KeyRecord("alias/csp-aes-bc",
                    generator.generateKey(), "AES", 256)
                    .origin("CSP_GENERATED(provider="
                            + generator.getProvider().getName() + ")"));
        });

        runCase("csp_generated#3 RSA from the default provider", () -> {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            register(new KeyRecord("alias/csp-rsa-default",
                    generator.generateKeyPair().getPublic(), "RSA", 2048)
                    .origin("CSP_GENERATED(provider="
                            + generator.getProvider().getName() + ")"));
        });
    }

    // services_encrypted_with_csp_generated_key (low) - SIMULATED label
    private static void servicesEncryptedWithCspGeneratedKey() {
        runCase("svc_csp#1 provider-generated AES-256", () ->
                serviceEncrypt("csp-aes-service",
                        register(new KeyRecord("alias/svc-csp-aes",
                                genSecret("AES", 256), "AES", 256)
                                .origin("CSP_GENERATED")),
                        "AES/GCM/NoPadding"));

        runCase("svc_csp#2 provider-generated RSA-2048", () ->
                serviceEncrypt("csp-rsa-service",
                        register(new KeyRecord("alias/svc-csp-rsa",
                                genRsa(2048).getPublic(), "RSA", 2048)
                                .origin("CSP_GENERATED")),
                        "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"));

        runCase("svc_csp#3 provider-generated AES-128", () ->
                serviceEncrypt("csp-cbc-service",
                        register(new KeyRecord("alias/svc-csp-aes128",
                                genSecret("AES", 128), "AES", 128)
                                .origin("CSP_GENERATED")),
                        "AES/CBC/PKCS5Padding"));
    }

    // services_encrypted_with_platform_managed_key (low)
    // REAL (#1: JVM default trust store), SIMULATED (#2, #3)
    private static void servicesEncryptedWithPlatformManagedKey() {
        runCase("svc_platform#1 public key from the JVM default trust store", () ->
                serviceEncrypt("platform-truststore-service",
                        "RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
                        firstRsaTrustAnchorKey()));

        runCase("svc_platform#2 platform default storage key", () ->
                serviceEncrypt("platform-storage-service",
                        register(new KeyRecord(
                                "alias/platform/default-storage-key",
                                genSecret("AES", 256), "AES", 256)
                                .origin("PLATFORM_MANAGED")),
                        "AES/GCM/NoPadding"));

        runCase("svc_platform#3 platform default database key", () ->
                serviceEncrypt("platform-database-service",
                        register(new KeyRecord(
                                "alias/platform/default-database-key",
                                genSecret("AES", 256), "AES", 256)
                                .origin("PLATFORM_MANAGED")),
                        "AES/CBC/PKCS5Padding"));
    }

    private static PublicKey firstRsaTrustAnchorKey() throws Exception {
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        try (InputStream in = Files.newInputStream(Paths.get(
                System.getProperty("java.home"),
                "lib", "security", "cacerts"))) {
            trustStore.load(in, "changeit".toCharArray());
        }
        for (String alias : Collections.list(trustStore.aliases())) {
            Certificate certificate = trustStore.getCertificate(alias);
            if (certificate != null
                    && "RSA".equals(certificate.getPublicKey().getAlgorithm())) {
                return certificate.getPublicKey();
            }
        }
        throw new IllegalStateException(
                "No RSA trust anchor found in the default trust store");
    }

    // cross_account_keys (critical) - SIMULATED
    private static void crossAccountKeys() {
        runCase("cross_account#1 AES key owned by another account", () ->
                register(new KeyRecord("alias/xacct-aes",
                        genSecret("AES", 256), "AES", 256)
                        .owner("111111111111").caller("222222222222")));

        runCase("cross_account#2 RSA key owned by another account", () ->
                register(new KeyRecord("alias/xacct-rsa",
                        genRsa(2048).getPublic(), "RSA", 2048)
                        .owner("333333333333").caller("444444444444")));

        runCase("cross_account#3 key owned by an external organisation", () ->
                register(new KeyRecord("alias/xacct-external",
                        genSecret("AES", 128), "AES", 128)
                        .owner("external-partner-555555555555")
                        .caller("111111111111")));
    }

    // services_encrypted_with_cross_account_key (critical) - SIMULATED
    private static void servicesEncryptedWithCrossAccountKey() {
        runCase("svc_xacct#1 service in account B uses account A key", () ->
                serviceEncrypt("xacct-aes-service",
                        register(new KeyRecord("alias/svc-xacct-aes",
                                genSecret("AES", 256), "AES", 256)
                                .owner("111111111111")
                                .caller("222222222222")),
                        "AES/GCM/NoPadding"));

        runCase("svc_xacct#2 service uses RSA key from another account", () ->
                serviceEncrypt("xacct-rsa-service",
                        register(new KeyRecord("alias/svc-xacct-rsa",
                                genRsa(2048).getPublic(), "RSA", 2048)
                                .owner("333333333333")
                                .caller("444444444444")),
                        "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"));

        runCase("svc_xacct#3 service uses key from external partner", () ->
                serviceEncrypt("xacct-partner-service",
                        register(new KeyRecord("alias/svc-xacct-partner",
                                genSecret("AES", 128), "AES", 128)
                                .owner("external-partner-555555555555")
                                .caller("111111111111")),
                        "AES/CBC/PKCS5Padding"));
    }
}