package com.prodguard.checks.premium.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import com.prodguard.checks.support.MockProdGuardContext;
import com.prodguard.core.CheckResult;
import com.prodguard.core.ProdGuardContext;

class EffectiveHttpsCheckTest {

    @Test
    void failsWhenPortIsUnavailable() {
        ProdGuardContext ctx = new MockProdGuardContext();

        EffectiveHttpsCheck check = new EffectiveHttpsCheck();

        Optional<CheckResult> result = check.check(ctx);

        assertTrue(result.isPresent());
        assertEquals("PG-202", result.get().descriptor().code());
    }

    @Test
    void passesOnHttpsRedirect() {
        StubHttpResponse response =
            new StubHttpResponse(
                301,
                Map.of("Location", List.of("https://example.com"))
            );

        EffectiveHttpsCheck check =
            new EffectiveHttpsCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8080);

        assertTrue(check.check(ctx).isEmpty());
    }

    @Test
    void failsOnRedirectWithoutHttps() {
        StubHttpResponse response =
            new StubHttpResponse(
                302,
                Map.of("Location", List.of("http://example.com"))
            );

        EffectiveHttpsCheck check =
            new EffectiveHttpsCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8080);

        assertTrue(check.check(ctx).isPresent());
    }

    @Test
    void passesOnHttpRejection() {
        StubHttpResponse response =
            new StubHttpResponse(403, Map.of());

        EffectiveHttpsCheck check =
            new EffectiveHttpsCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8080);

        assertTrue(check.check(ctx).isEmpty());
    }

    @Test
    void failsOnPlainHttpAcceptance() {
        StubHttpResponse response =
            new StubHttpResponse(200, Map.of());

        EffectiveHttpsCheck check =
            new EffectiveHttpsCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8080);

        Optional<CheckResult> result = check.check(ctx);

        assertTrue(result.isPresent());
        assertEquals("PG-202", result.get().descriptor().code());
    }
}
