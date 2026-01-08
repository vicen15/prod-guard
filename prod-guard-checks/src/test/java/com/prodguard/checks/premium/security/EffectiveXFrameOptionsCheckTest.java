package com.prodguard.checks.premium.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import com.prodguard.checks.support.MockProdGuardContext;
import com.prodguard.core.CheckResult;
import com.prodguard.core.ProdGuardContext;

class EffectiveXFrameOptionsCheckTest {

    @Test
    void passesWhenXFrameOptionsDenyIsPresent() {

        StubHttpResponse response =
            new StubHttpResponse(
                200,
                Map.of(
                    "X-Frame-Options",
                    List.of("DENY")
                )
            );

        EffectiveXFrameOptionsCheck check =
            new EffectiveXFrameOptionsCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        Optional<CheckResult> result = check.check(ctx);

        assertThat(result).isEmpty();
    }

    @Test
    void passesWhenXFrameOptionsSameOriginIsPresent() {

        StubHttpResponse response =
            new StubHttpResponse(
                200,
                Map.of(
                    "X-Frame-Options",
                    List.of("SAMEORIGIN")
                )
            );

        EffectiveXFrameOptionsCheck check =
            new EffectiveXFrameOptionsCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        Optional<CheckResult> result = check.check(ctx);

        assertThat(result).isEmpty();
    }

    @Test
    void passesWhenCspFrameAncestorsIsPresent() {

        StubHttpResponse response =
            new StubHttpResponse(
                200,
                Map.of(
                    "Content-Security-Policy",
                    List.of("default-src 'self'; frame-ancestors 'none'")
                )
            );

        EffectiveXFrameOptionsCheck check =
            new EffectiveXFrameOptionsCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        Optional<CheckResult> result = check.check(ctx);

        assertThat(result).isEmpty();
    }

    @Test
    void failsWhenXFrameOptionsHasInvalidValue() {

        StubHttpResponse response =
            new StubHttpResponse(
                200,
                Map.of(
                    "X-Frame-Options",
                    List.of("ALLOWALL")
                )
            );

        EffectiveXFrameOptionsCheck check =
            new EffectiveXFrameOptionsCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        CheckResult result =
            check.check(ctx).orElseThrow();

        assertThat(result.message())
            .contains("Invalid X-Frame-Options");
    }

    @Test
    void failsWhenNoClickjackingProtectionIsPresent() {

        StubHttpResponse response =
            new StubHttpResponse(
                200,
                Map.of()
            );

        EffectiveXFrameOptionsCheck check =
            new EffectiveXFrameOptionsCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        CheckResult result =
            check.check(ctx).orElseThrow();

        assertThat(result.message())
            .contains("No clickjacking protection");
    }

    @Test
    void failsWhenLocalServerPortIsUnavailable() {

        EffectiveXFrameOptionsCheck check =
            new EffectiveXFrameOptionsCheck(req -> {
                throw new AssertionError("HTTP must not be invoked");
            });

        ProdGuardContext ctx =
            new MockProdGuardContext();

        CheckResult result =
            check.check(ctx).orElseThrow();

        assertThat(result.message())
            .contains("Local server port");
    }

    @Test
    void failsWhenHttpProbeThrowsException() {

        EffectiveXFrameOptionsCheck check =
            new EffectiveXFrameOptionsCheck(req -> {
                throw new RuntimeException("boom");
            });

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        CheckResult result =
            check.check(ctx).orElseThrow();

        assertThat(result.message())
            .contains("Failed to perform HTTPS request");
    }
}
