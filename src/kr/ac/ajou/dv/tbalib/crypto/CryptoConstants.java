package kr.ac.ajou.dv.tbalib.crypto;

public class CryptoConstants {
    public static final int PUBLIC_KEY_BITS = 1024;
    public static final int PUBLIC_KEY_BYTES = PUBLIC_KEY_BITS / 8;
    public static final int MAX_CRYPTO_BYTES = (PUBLIC_KEY_BITS == 512) ? 53 : ((PUBLIC_KEY_BITS == 1024) ? 117 : 245);

    public static final String DIGEST_ALGORITHM = "SHA-1";
}
