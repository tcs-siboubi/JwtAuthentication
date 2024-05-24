package org.example;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.List;

/**
 * Utility class for working with JSON Web Tokens (JWT).
 * Provides methods for token validation, generation, and key management.
 */
@Slf4j
public class JwtUtils {

    private static final long VALIDITY_IN_MILLISECONDS = 86400000;// 24 hrs
    private static final String ISSUER = "The Container Store";

    /**
     * Generates an access token using the provided user information and private key.
     *
     * @param userId the unique identifier of the user
     * @param userName the name of the user
     * @param roleArray the list of roles assigned to the user
     * @param jwtPrivateKey the private key in string format used to sign the token
     * @return the generated access token
     * @throws NoSuchAlgorithmException if the specified algorithm is not available
     * @throws InvalidKeySpecException if the given key specification is inappropriate
     */
    public String generateAccessToken(
            final String userId,
            final String userName,
            final List<String> roleArray,
            final String jwtPrivateKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        return Jwts.builder()
                .setId(userId)
                .setSubject(userName)
                .claim("roles", roleArray)
                .setIssuer(ISSUER)
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + VALIDITY_IN_MILLISECONDS))
                .signWith(SignatureAlgorithm.RS256, generateJwtKeyEncryption(jwtPrivateKey))
                .compact();
    }

    /**
     * Generates a public key for JWT decryption using the given public key string.
     *
     * @param jwtPublicKey the public key in string format used to generate the PublicKey object
     * @return the generated PublicKey object
     * @throws NoSuchAlgorithmException if the specified algorithm is not available
     * @throws InvalidKeySpecException if the given key specification is inappropriate
     */
    public PublicKey generateJwtKeyDecryption(String jwtPublicKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] keyBytes = Base64.decodeBase64(jwtPublicKey);
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);
        return keyFactory.generatePublic(x509EncodedKeySpec);
    }

    /**
     * Generates a private key for JWT encryption using the given private key string.
     *
     * @param jwtPrivateKey the private key in string format used to generate the PrivateKey object
     * @return the generated PrivateKey object
     * @throws NoSuchAlgorithmException if the specified algorithm is not available
     * @throws InvalidKeySpecException if the given key specification is inappropriate
     */
    public PrivateKey generateJwtKeyEncryption(String jwtPrivateKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] keyBytes = Base64.decodeBase64(jwtPrivateKey);
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyBytes);
        return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
    }

    /**
     * Validates a JWT token using the provided public key.
     *
     * @param authToken the JWT token to validate
     * @param jwtPublicKey the public key used to validate the JWT token
     * @return true if the token is valid, false otherwise
     */
    public boolean validateJwtToken(String authToken, String jwtPublicKey) {
        try {
            Jwts.parser()
                    .setSigningKey(generateJwtKeyDecryption(jwtPublicKey))
                    .parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            log.error("Invalid JWT signature: {}" + e.getMessage());
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token: {}" + e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("JWT token is expired: {}" + e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported: {}" + e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}" + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            log.error("no such algorithm exception");
        } catch (InvalidKeySpecException e) {
            log.error("invalid key exception");
        }

        return false;
    }

    /**
     * Prints the structure of the given token using the provided public key.
     *
     * @param token the token whose structure needs to be printed
     * @param publicKey the public key used to validate the token
     */
    public void printStructure(String token, PublicKey publicKey) {
        try {
            Jws<Claims> parseClaimsJws = Jwts.parser()
                    .setSigningKey(publicKey)
                    .parseClaimsJws(token);

            log.info("Header     : " + parseClaimsJws.getHeader());
            log.info("Body       : " + parseClaimsJws.getBody());
            log.info("Signature  : " + parseClaimsJws.getSignature());
        } catch (SignatureException e) {
            log.error("Invalid JWT signature: {}" + e.getMessage());
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token: {}" + e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("JWT token is expired: {}" + e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported: {}" + e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}" + e.getMessage());
        }
    }

}
