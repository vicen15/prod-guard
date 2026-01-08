package com.prodguard.checks.premium.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import com.prodguard.checks.premium.security.EffectiveCrossOriginOpenerPolicyCheck;
import com.prodguard.checks.support.MockProdGuardContext;
import com.prodguard.core.CheckResult;
import com.prodguard.core.ProdGuardContext;

class EffectiveCrossOriginOpenerPolicyCheckTest {

    @Test
    void passesWhenCoopIsSameOrigin() {

        StubHttpResponse response =
            new StubHttpResponse(
                200,
                Map.of(
                    "Cross-Origin-Opener-Policy",
                    List.of("same-origin")
                )
            );

        EffectiveCrossOriginOpenerPolicyCheck check =
            new EffectiveCrossOriginOpenerPolicyCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        Optional<CheckResult> result = check.check(ctx);

        assertThat(result).isEmpty();
    }

    @Test
    void passesWhenCoopIsSameOriginAllowPopups() {

        StubHttpResponse response =
            new StubHttpResponse(
                200,
                Map.of(
                    "Cross-Origin-Opener-Policy",
                    List.of("same-origin-allow-popups")
                )
            );

        EffectiveCrossOriginOpenerPolicyCheck check =
            new EffectiveCrossOriginOpenerPolicyCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        assertThat(check.check(ctx)).isEmpty();
    }

    @Test
    void failsWhenCoopHeaderIsMissing() {

        StubHttpResponse response =
            new StubHttpResponse(200, Map.of());

        EffectiveCrossOriginOpenerPolicyCheck check =
            new EffectiveCrossOriginOpenerPolicyCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        CheckResult result =
            check.check(ctx).orElseThrow();

        assertThat(result.descriptor().code())
            .isEqualTo("PG-209");

        assertThat(result.message())
            .contains("not present");
    }

    @Test
    void failsWhenCoopIsUnsafeValue() {

        StubHttpResponse response =
            new StubHttpResponse(
                200,
                Map.of(
                    "Cross-Origin-Opener-Policy",
                    List.of("unsafe-none")
                )
            );

        EffectiveCrossOriginOpenerPolicyCheck check =
            new EffectiveCrossOriginOpenerPolicyCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        CheckResult result =
            check.check(ctx).orElseThrow();

        assertThat(result.message())
            .contains("Weak Cross-Origin-Opener-Policy");
    }

    @Test
    void failsWhenLocalServerPortIsUnavailable() {

        EffectiveCrossOriginOpenerPolicyCheck check =
            new EffectiveCrossOriginOpenerPolicyCheck(req -> {
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

        EffectiveCrossOriginOpenerPolicyCheck check =
            new EffectiveCrossOriginOpenerPolicyCheck(req -> {
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
