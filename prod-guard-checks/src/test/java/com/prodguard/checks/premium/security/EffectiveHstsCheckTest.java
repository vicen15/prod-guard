package com.prodguard.checks.premium.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import com.prodguard.checks.support.MockProdGuardContext;
import com.prodguard.core.CheckResult;

class EffectiveHstsCheckTest {

    @Test
    void failsWhenPortIsUnavailable() {
        EffectiveHstsCheck check = new EffectiveHstsCheck();

        Optional<CheckResult> result =
            check.check(new MockProdGuardContext());

        assertTrue(result.isPresent());
        assertEquals("PG-203", result.get().descriptor().code());
    }

    @Test
    void failsWhenHstsHeaderIsMissing() {
        StubHttpResponse response =
            new StubHttpResponse(
                200,
                Map.of()
            );

        EffectiveHstsCheck check =
            new EffectiveHstsCheck(req -> response);

        MockProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        Optional<CheckResult> result = check.check(ctx);

        assertTrue(result.isPresent());
        assertEquals("PG-203", result.get().descriptor().code());
        assertTrue(result.get().message().contains("HSTS header"));
    }

    @Test
    void failsWhenHstsHasNoMaxAge() {
        StubHttpResponse response =
            new StubHttpResponse(
                200,
                Map.of(
                    "Strict-Transport-Security",
                    List.of("includeSubDomains")
                )
            );

        EffectiveHstsCheck check =
            new EffectiveHstsCheck(req -> response);

        MockProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        Optional<CheckResult> result = check.check(ctx);

        assertTrue(result.isPresent());
        assertTrue(result.get().message().contains("missing max-age"));
    }

    @Test
    void failsWhenHstsMaxAgeIsTooLow() {
        StubHttpResponse response =
            new StubHttpResponse(
                200,
                Map.of(
                    "Strict-Transport-Security",
                    List.of("max-age=300")
                )
            );

        EffectiveHstsCheck check =
            new EffectiveHstsCheck(req -> response);

        MockProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        Optional<CheckResult> result = check.check(ctx);

        assertTrue(result.isPresent());
        assertTrue(result.get().message().contains("too low"));
    }

    @Test
    void passesWhenHstsIsStrongEnough() {
        StubHttpResponse response =
            new StubHttpResponse(
                200,
                Map.of(
                    "Strict-Transport-Security",
                    List.of("max-age=31536000; includeSubDomains")
                )
            );

        EffectiveHstsCheck check =
            new EffectiveHstsCheck(req -> response);

        MockProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        Optional<CheckResult> result = check.check(ctx);

        assertTrue(result.isEmpty());
    }
}
