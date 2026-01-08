package com.prodguard.checks.premium.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import com.prodguard.checks.support.MockProdGuardContext;
import com.prodguard.core.CheckResult;
import com.prodguard.core.ProdGuardContext;

class EffectiveReferrerPolicyCheckTest {

    @Test
    void passesWhenSafeReferrerPolicyIsPresent() {

        StubHttpResponse response =
            new StubHttpResponse(
                200,
                Map.of(
                    "Referrer-Policy",
                    List.of("strict-origin-when-cross-origin")
                )
            );

        EffectiveReferrerPolicyCheck check =
            new EffectiveReferrerPolicyCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        Optional<CheckResult> result = check.check(ctx);

        assertThat(result).isEmpty();
    }

    @Test
    void failsWhenReferrerPolicyHeaderIsMissing() {

        StubHttpResponse response =
            new StubHttpResponse(200, Map.of());

        EffectiveReferrerPolicyCheck check =
            new EffectiveReferrerPolicyCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        CheckResult result =
            check.check(ctx).orElseThrow();

        assertThat(result.descriptor().code())
            .isEqualTo("PG-207");

        assertThat(result.message())
            .contains("not present");
    }

    @Test
    void failsWhenWeakReferrerPolicyIsUsed() {

        StubHttpResponse response =
            new StubHttpResponse(
                200,
                Map.of(
                    "Referrer-Policy",
                    List.of("unsafe-url")
                )
            );

        EffectiveReferrerPolicyCheck check =
            new EffectiveReferrerPolicyCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        CheckResult result =
            check.check(ctx).orElseThrow();

        assertThat(result.message())
            .contains("Weak Referrer-Policy");

        assertThat(result.message())
            .contains("unsafe-url");
    }

    @Test
    void failsWhenLocalServerPortIsUnavailable() {

        EffectiveReferrerPolicyCheck check =
            new EffectiveReferrerPolicyCheck(req -> {
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

        EffectiveReferrerPolicyCheck check =
            new EffectiveReferrerPolicyCheck(req -> {
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

    @Test
    void policyValueIsHandledCaseInsensitively() {

        StubHttpResponse response =
            new StubHttpResponse(
                200,
                Map.of(
                    "Referrer-Policy",
                    List.of("No-Referrer")
                )
            );

        EffectiveReferrerPolicyCheck check =
            new EffectiveReferrerPolicyCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        Optional<CheckResult> result = check.check(ctx);

        assertThat(result).isEmpty();
    }
}
