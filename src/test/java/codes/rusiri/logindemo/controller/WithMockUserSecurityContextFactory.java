package codes.rusiri.logindemo.controller;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

import codes.rusiri.logindemo.security.UserPrincipal;
import codes.rusiri.logindemo.security.UserPrincipalAuthenticationToken;

import java.util.Arrays;

public class WithMockUserSecurityContextFactory implements WithSecurityContextFactory<WithMockUser> {
    @Override
    public SecurityContext createSecurityContext(WithMockUser annotation) {
        var authorities = Arrays.stream(annotation.authorities())
                .map(SimpleGrantedAuthority::new)
                .toList();

        var principal = UserPrincipal.builder()
                .userId(annotation.userId())
                .email("test@test.com")
                .authorities(authorities)
                .build();

        var context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(new UserPrincipalAuthenticationToken(principal));
        return context;
    }
}
