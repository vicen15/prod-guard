package com.prodguard.checks.free;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import com.prodguard.checks.free.SecurityHeadersCheck;
import com.prodguard.checks.support.MockProdGuardContext;

class SecurityHeadersCheckTest {

    private final SecurityHeadersCheck check = new SecurityHeadersCheck();

    @Test
    void warnsWhenSpringSecurityIsMissing() {
        var ctx = new MockProdGuardContext();

        var result = check.check(ctx);

        assertTrue(result.isPresent());
        assertEquals("PG-006", result.get().code());
    }

    @Test
    void passesWhenSecurityFilterChainExists() {
        var ctx = new MockProdGuardContext()
                .withBean(
                    "org.springframework.security.web.SecurityFilterChain",
                    new Object()
                );

        assertTrue(check.check(ctx).isEmpty());
    }
}
