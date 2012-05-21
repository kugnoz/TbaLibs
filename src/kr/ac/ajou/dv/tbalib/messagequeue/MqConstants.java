package kr.ac.ajou.dv.tbalib.messagequeue;

public class MqConstants {
    public static final String EXCHANGE_NAME = "tba";
    public static final String ROUTING_CREATE = "signup.";
    public static final String ROUTING_CREATE_ACK = "signup_ack.";
    public static final String ROUTING_LOGIN = "signin.";
    public static final String REPLY_STRING = "REPLY";
    public static final String ACK_STRING = "ACK";
    public static final String FAIL_STRING = "FAIL";

    // unit: second
    public static final int CREATE_TIMEOUT = 60;
    public static final int CREATE_ACK_TIMEOUT = 30;

    public static final int LOGIN_TIMEOUT = 60;
}
