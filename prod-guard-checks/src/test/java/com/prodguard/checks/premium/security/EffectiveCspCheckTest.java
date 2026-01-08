package com.prodguard.checks.premium.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import com.prodguard.checks.premium.security.EffectiveCspCheck;
import com.prodguard.checks.support.MockProdGuardContext;
import com.prodguard.core.CheckResult;
import com.prodguard.core.ProdGuardContext;

class EffectiveCspCheckTest {

    @Test
    void passesWhenStrictCspIsPresent() {

        StubHttpResponse response =
            new StubHttpResponse(
                200,
                Map.of(
                    "Content-Security-Policy",
                    List.of("default-src 'self'; script-src 'self'")
                )
            );

        EffectiveCspCheck check =
            new EffectiveCspCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        Optional<CheckResult> result = check.check(ctx);

        assertThat(result).isEmpty();
    }

    @Test
    void failsWhenCspIsMissing() {

        StubHttpResponse response =
            new StubHttpResponse(200, Map.of());

        EffectiveCspCheck check =
            new EffectiveCspCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        CheckResult result =
            check.check(ctx).orElseThrow();

        assertThat(result.descriptor().code())
            .isEqualTo("PG-204");

        assertThat(result.message())
            .contains("not present");
    }

    @Test
    void failsWhenCspIsReportOnly() {

        StubHttpResponse response =
            new StubHttpResponse(
                200,
                Map.of(
                    "Content-Security-Policy-Report-Only",
                    List.of("default-src 'self'")
                )
            );

        EffectiveCspCheck check =
            new EffectiveCspCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        CheckResult result =
            check.check(ctx).orElseThrow();

        assertThat(result.message())
            .contains("report-only");
    }

    @Test
    void failsWhenCspContainsUnsafeInline() {

        StubHttpResponse response =
            new StubHttpResponse(
                200,
                Map.of(
                    "Content-Security-Policy",
                    List.of("default-src 'self'; script-src 'unsafe-inline'")
                )
            );

        EffectiveCspCheck check =
            new EffectiveCspCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        CheckResult result =
            check.check(ctx).orElseThrow();

        assertThat(result.message())
            .contains("unsafe-inline");
    }

    @Test
    void failsWhenCspAllowsWildcardDefaultSrc() {

        StubHttpResponse response =
            new StubHttpResponse(
                200,
                Map.of(
                    "Content-Security-Policy",
                    List.of("default-src *; script-src 'self'")
                )
            );

        EffectiveCspCheck check =
            new EffectiveCspCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        CheckResult result =
            check.check(ctx).orElseThrow();

        assertThat(result.message())
            .contains("wildcard");
    }

    @Test
    void failsWhenLocalPortIsUnavailable() {

        EffectiveCspCheck check =
            new EffectiveCspCheck(req -> {
                throw new AssertionError("HTTP must not be invoked");
            });

        ProdGuardContext ctx =
            new MockProdGuardContext();

        CheckResult result =
            check.check(ctx).orElseThrow();

        assertThat(result.message())
            .contains("local server port");
    }

    @Test
    void failsWhenHttpProbeThrowsException() {

        EffectiveCspCheck check =
            new EffectiveCspCheck(req -> {
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
