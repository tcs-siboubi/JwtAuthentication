package org.example;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static java.lang.String.*;

/**
 * Main class for the JWT Authentication Application.
 * This class serves as the entry point for the application.
 */
@Slf4j
public class JwtAuthenticationApplication {

    /**
     * The default user name used in the application.
     * Change this value as needed for different scenarios.
     */
    protected static final String USER_NAME = "Siboubi";
    /**
     * List of roles available in the application.
     * In this example, there's only one role: ADMIN.
     */
    protected static final List<String> ROLE_ARRAY = List.of("ADMIN");

    /**
     * Entry point of the JwtAuthenticationApplication.
     * Initializes and starts the Spring Boot application.
     *
     * @param args Command line arguments
     */
    public static void main(String[] args) {
        log.debug("Hello, World!");
        try {
            JwtAuthenticationApplication jwtAuthenticationApplication = new JwtAuthenticationApplication();
            jwtAuthenticationApplication.generateJWTWithRsa();
            log.debug("Hello, World09!");
        } catch (Exception e) {
            log.error("Hello, World13!");
            e.printStackTrace();
            log.error("Hello, World14!");
        }
        log.debug("Hello, World15!");
    }

    /**
     * Generates a JSON Web Token (JWT) using RSA encryption.
     *
     * @throws NoSuchAlgorithmException   if the algorithm for RSA key generation is not available.
     * @throws InvalidKeySpecException    if the provided key specification is invalid.
     */
    public void generateJWTWithRsa() throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        log.debug("Hello, World01!");
        kpg.initialize(2048);
        log.debug("Hello, World02!");
        KeyPair keyPair = kpg.generateKeyPair();
        log.debug("Hello, World03!");

        String publicKey = Base64.encodeBase64String(keyPair.getPublic().getEncoded());
        log.info(format("Hello, World04! publicKey: %s", publicKey));
        String privateKey = Base64.encodeBase64String(keyPair.getPrivate().getEncoded());
        log.info(format("Hello, World05! privateKey: %s", privateKey));
        JwtUtils jwtUtils = new JwtUtils();
        log.info("Hello, World06!");
        log.info(format(
                "Hello, World07! encodeBase64PrivateKey: %s",
                Base64.encodeBase64String(keyPair.getPrivate().getEncoded())));
        log.info(format(
                "Hello, World08! encodeBase64PublicKey: %s",
                Base64.encodeBase64String(keyPair.getPublic().getEncoded())));
        String id = UUID.randomUUID().toString();
        String jwtToken = jwtUtils.generateAccessToken(id, USER_NAME, ROLE_ARRAY, privateKey);
        log.info(format("Hello, World09! jwtToken: %s", jwtToken));
        log.info(format(
                "Hello, World10! validateJwtToken: %s",
                jwtUtils.validateJwtToken(jwtToken, publicKey)));
        log.debug("Hello, World11!");
        jwtUtils.printStructure(jwtToken, keyPair.getPublic());
        log.debug("Hello, World12!");
    }
}