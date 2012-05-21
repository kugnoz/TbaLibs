package kr.ac.ajou.dv.tbalib.authtoken;

public class InvalidAuthenticationTokenException extends Exception {
    public InvalidAuthenticationTokenException(String s) {
        super(s);
    }
}
