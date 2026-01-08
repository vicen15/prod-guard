package com.prodguard.checks.premium.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import com.prodguard.checks.support.MockProdGuardContext;
import com.prodguard.core.CheckResult;
import com.prodguard.core.ProdGuardContext;

class EffectivePermissionsPolicyCheckTest {

    @Test
    void passesWhenRestrictivePermissionsPolicyIsPresent() {

        StubHttpResponse response =
            new StubHttpResponse(
                200,
                Map.of(
                    "Permissions-Policy",
                    List.of(
                        "camera=(), microphone=(), geolocation=(), payment=()"
                    )
                )
            );

        EffectivePermissionsPolicyCheck check =
            new EffectivePermissionsPolicyCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        Optional<CheckResult> result = check.check(ctx);

        assertThat(result).isEmpty();
    }

    @Test
    void failsWhenPermissionsPolicyIsMissing() {

        StubHttpResponse response =
            new StubHttpResponse(200, Map.of());

        EffectivePermissionsPolicyCheck check =
            new EffectivePermissionsPolicyCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        CheckResult result =
            check.check(ctx).orElseThrow();

        assertThat(result.descriptor().code())
            .isEqualTo("PG-208");

        assertThat(result.message())
            .contains("not present");
    }

    @Test
    void failsWhenSensitiveFeatureIsUnrestricted() {

        StubHttpResponse response =
            new StubHttpResponse(
                200,
                Map.of(
                    "Permissions-Policy",
                    List.of("camera=*, microphone=()")
                )
            );

        EffectivePermissionsPolicyCheck check =
            new EffectivePermissionsPolicyCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        CheckResult result =
            check.check(ctx).orElseThrow();

        assertThat(result.message())
            .contains("camera");

        assertThat(result.message())
            .contains("Unrestricted");
    }

    @Test
    void failsWhenAnotherSensitiveFeatureIsUnrestricted() {

        StubHttpResponse response =
            new StubHttpResponse(
                200,
                Map.of(
                    "Permissions-Policy",
                    List.of("geolocation=*")
                )
            );

        EffectivePermissionsPolicyCheck check =
            new EffectivePermissionsPolicyCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        CheckResult result =
            check.check(ctx).orElseThrow();

        assertThat(result.message())
            .contains("geolocation");
    }

    @Test
    void failsWhenLocalServerPortIsUnavailable() {

        EffectivePermissionsPolicyCheck check =
            new EffectivePermissionsPolicyCheck(req -> {
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

        EffectivePermissionsPolicyCheck check =
            new EffectivePermissionsPolicyCheck(req -> {
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
