package codes.rusiri.logindemo.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtIssuer {
    private final JwtProperties properties;

    /**
     * This methid will issue a JWT token
     * 
     * @param request
     * @return
     */
    public String issue(Request request) {
        var now = Instant.now();

        return JWT.create()
                .withSubject(String.valueOf(request.userId))
                //sets an 
                .withIssuedAt(now)
                //sets an expiration
                .withExpiresAt(now.plus(properties.getTokenDuration()))
                .withClaim("e", request.getEmail())
                .withClaim("au", request.getRoles())
                // encrypted using algorith by taking the secretkey in the yml file
                .sign(Algorithm.HMAC256(properties.getSecretKey()));
    }

    @Getter
    @Builder
    public static class Request {
        private final Long userId;
        private final String email;
        private final List<String> roles;
    }
}
