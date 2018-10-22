package jwedecrypt;

public class JWTVerificationException extends RuntimeException {
    public JWTVerificationException() {
        this("JWT signature verification failed.", null);
    }

    public JWTVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}