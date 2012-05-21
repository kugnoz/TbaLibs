package kr.ac.ajou.dv.tbalib.authtoken;

import kr.ac.ajou.dv.tbalib.crypto.CryptoConstants;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class AuthToken {
    public static final String TOKEN_CRYPTO_ALGORITHM = "RSA";
    public static final String TOKEN_SIGNATURE_ALGORITHM = "DSA";
    public static final String TOKEN_CRYPTO_ALGORITHM_WITH_PADDING_SCHEME = "RSA/ECB/PKCS1Padding";
    public static final String TOKEN_SIGNATURE_ALGORITHM_WITH_DIGEST_SCHEME = "SHA1withDSA";

    public static final String URL_SIGNUP_INTERFACE = "/tbaCreateInterface.jsp";
    public static final String URL_SIGNUP_ACK_INTERFACE = "/tbaCreateAckInterface.jsp";
    public static final String URL_SIGNIN_INTERFACE = "/tbaLoginInterface.jsp";

    public static final int NONCE_SIZE = 8; // bytes
    public static final int LENGTH_FIELD_SIZE = 4; // size of integer

    public static AuthToken parseAuthTokenFromByteArray(byte[] d) throws InvalidAuthenticationTokenException {
        int pos = 0;
        int len = byteArrayToInt(Arrays.copyOfRange(d, pos, pos + LENGTH_FIELD_SIZE));
        pos += LENGTH_FIELD_SIZE;
        byte[] tPubKey = Arrays.copyOfRange(d, pos, pos + len);
        pos += len;
        len = byteArrayToInt(Arrays.copyOfRange(d, pos, pos + LENGTH_FIELD_SIZE));
        pos += LENGTH_FIELD_SIZE;
        byte[] tNonce = Arrays.copyOfRange(d, pos, pos + len);
        pos += len;
        len = byteArrayToInt(Arrays.copyOfRange(d, pos, pos + LENGTH_FIELD_SIZE));
        pos += LENGTH_FIELD_SIZE;
        byte[] tSig = Arrays.copyOfRange(d, pos, pos + len);
        return new AuthToken(tPubKey, tNonce, tSig);
    }

    public static AuthToken decrypt(byte[] ciphertext, PrivateKey privateKey) throws InvalidAuthenticationTokenException {
        AuthToken token;
        try {
            Cipher cipher = Cipher.getInstance(TOKEN_CRYPTO_ALGORITHM_WITH_PADDING_SCHEME);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            int chunks = (int) Math.ceil((double) ciphertext.length / CryptoConstants.PUBLIC_KEY_BYTES);
            ByteBuffer bb = ByteBuffer.allocate(CryptoConstants.MAX_CRYPTO_BYTES * chunks);

            for (int i = 0; i < chunks; i++) {
                byte[] cut = Arrays.copyOfRange(
                        ciphertext,
                        CryptoConstants.PUBLIC_KEY_BYTES * i,
                        CryptoConstants.PUBLIC_KEY_BYTES * (i + 1));
                byte[] decrypted = cipher.doFinal(cut);
                bb.put(decrypted);
            }
            token = AuthToken.parseAuthTokenFromByteArray(bb.array());
        } catch (Exception e) {
            throw new InvalidAuthenticationTokenException(e.toString());
        }
        return token;
    }

    private static int byteArrayToInt(byte[] b) {
        return (b[0] << 24)
                + ((b[1] & 0xFF) << 16)
                + ((b[2] & 0xFF) << 8)
                + (b[3] & 0xFF);
    }

    private byte[] publicKey;
    private byte[] nonce;
    private byte[] signature;

    private int sizeOfPubKey;
    private int sizeOfNonce;
    private int sizeOfSignature;

    public AuthToken(byte[] pubkey, byte[] n, byte[] sig) throws InvalidAuthenticationTokenException {
        if (pubkey == null || n == null || sig == null) {
            throw new InvalidAuthenticationTokenException("Invalid auth token");
        }
        publicKey = pubkey;
        nonce = n;
        signature = sig;

        sizeOfPubKey = pubkey.length;
        sizeOfNonce = n.length;
        sizeOfSignature = sig.length;
    }

    public byte[] encrypt(byte[] key) {
        byte[] source = this.toByteArray();
        byte[] encrypted = null;

        try {
            // set the public key (with web apps)
            KeyFactory keyFactory = KeyFactory.getInstance(TOKEN_CRYPTO_ALGORITHM);
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(key);
            RSAPublicKey rsaKey = (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);
            Cipher c = Cipher.getInstance(TOKEN_CRYPTO_ALGORITHM_WITH_PADDING_SCHEME);
            c.init(Cipher.ENCRYPT_MODE, rsaKey);

            // multi-block encryption
            int chunks = (int) Math.ceil((double) source.length / CryptoConstants.MAX_CRYPTO_BYTES);
            ByteBuffer bb = ByteBuffer.allocate(CryptoConstants.PUBLIC_KEY_BYTES * chunks);
            for (int i = 0; i < chunks; i++) {
                byte[] cut = Arrays.copyOfRange(
                        source,
                        CryptoConstants.MAX_CRYPTO_BYTES * i,
                        CryptoConstants.MAX_CRYPTO_BYTES * (i + 1));
                bb.put(c.doFinal(cut));
            }
            encrypted = bb.array();
        } catch (Exception e) {
            encrypted = null;
        }
        return encrypted;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public byte[] getNonce() {
        return nonce;
    }

    public String getNonceString() {
        return new String(nonce);
    }

    public byte[] getSignature() {
        return signature;
    }

    public byte[] toByteArray() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(intToByteArray(sizeOfPubKey), 0, LENGTH_FIELD_SIZE);
        baos.write(publicKey, 0, publicKey.length);
        baos.write(intToByteArray(sizeOfNonce), 0, LENGTH_FIELD_SIZE);
        baos.write(nonce, 0, nonce.length);
        baos.write(intToByteArray(sizeOfSignature), 0, LENGTH_FIELD_SIZE);
        baos.write(signature, 0, signature.length);
        byte[] randomBytes = new SecureRandom().generateSeed(NONCE_SIZE);
        baos.write(randomBytes, 0, randomBytes.length);
        return baos.toByteArray();
    }

    public boolean verify() throws InvalidAuthenticationTokenException {
        boolean ok;
        try {
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKey);
            KeyFactory keyFactory = KeyFactory.getInstance(TOKEN_SIGNATURE_ALGORITHM);
            PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
            Signature sig = Signature.getInstance(TOKEN_SIGNATURE_ALGORITHM_WITH_DIGEST_SCHEME);
            sig.initVerify(pubKey);
            sig.update(nonce);
            ok = sig.verify(signature);
        } catch (InvalidKeySpecException e) {
            throw new InvalidAuthenticationTokenException("Authentication token: Invalid public key.");
        } catch (InvalidKeyException e) {
            throw new InvalidAuthenticationTokenException("Authentication token: This public key is invalid to verify.");
        } catch (SignatureException e) {
            throw new InvalidAuthenticationTokenException("Authentication token: Fail to verify the signature.");
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidAuthenticationTokenException("This host does not support DSA algorithm.");
        }
        return ok;
    }

    private byte[] intToByteArray(int n) {
        return new byte[]{
                (byte) (n >>> 24),
                (byte) (n >>> 16),
                (byte) (n >>> 8),
                (byte) n
        };
    }
}
