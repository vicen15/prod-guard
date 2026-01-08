package com.prodguard.checks.premium.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import com.prodguard.checks.premium.security.EffectiveCookieFlagsCheck;
import com.prodguard.checks.support.MockProdGuardContext;
import com.prodguard.core.CheckResult;
import com.prodguard.core.ProdGuardContext;

class EffectiveCookieFlagsCheckTest {

    @Test
    void passesWhenNoCookiesAreReturned() {

        StubHttpResponse response =
            new StubHttpResponse(200, Map.of());

        EffectiveCookieFlagsCheck check =
            new EffectiveCookieFlagsCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        Optional<CheckResult> result = check.check(ctx);

        assertThat(result).isEmpty();
    }

    @Test
    void passesWhenCookieHasAllRequiredFlags() {

        StubHttpResponse response =
            new StubHttpResponse(
                200,
                Map.of(
                    "Set-Cookie",
                    List.of(
                        "SESSION=abc123; Secure; HttpOnly; SameSite=Strict"
                    )
                )
            );

        EffectiveCookieFlagsCheck check =
            new EffectiveCookieFlagsCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        Optional<CheckResult> result = check.check(ctx);

        assertThat(result).isEmpty();
    }

    @Test
    void failsWhenCookieIsMissingSecure() {

        StubHttpResponse response =
            new StubHttpResponse(
                200,
                Map.of(
                    "Set-Cookie",
                    List.of(
                        "SESSION=abc123; HttpOnly; SameSite=Strict"
                    )
                )
            );

        EffectiveCookieFlagsCheck check =
            new EffectiveCookieFlagsCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        CheckResult result =
            check.check(ctx).orElseThrow();

        assertThat(result.message())
            .contains("Secure");
    }

    @Test
    void failsWhenCookieIsMissingHttpOnly() {

        StubHttpResponse response =
            new StubHttpResponse(
                200,
                Map.of(
                    "Set-Cookie",
                    List.of(
                        "SESSION=abc123; Secure; SameSite=Strict"
                    )
                )
            );

        EffectiveCookieFlagsCheck check =
            new EffectiveCookieFlagsCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        CheckResult result =
            check.check(ctx).orElseThrow();

        assertThat(result.message())
            .contains("HttpOnly");
    }

    @Test
    void failsWhenCookieIsMissingSameSite() {

        StubHttpResponse response =
            new StubHttpResponse(
                200,
                Map.of(
                    "Set-Cookie",
                    List.of(
                        "SESSION=abc123; Secure; HttpOnly"
                    )
                )
            );

        EffectiveCookieFlagsCheck check =
            new EffectiveCookieFlagsCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        CheckResult result =
            check.check(ctx).orElseThrow();

        assertThat(result.message())
            .contains("SameSite");
    }

    @Test
    void failsWhenSameSiteNoneIsUsedWithoutSecure() {

        StubHttpResponse response =
            new StubHttpResponse(
                200,
                Map.of(
                    "Set-Cookie",
                    List.of(
                        "SESSION=abc123; HttpOnly; SameSite=None"
                    )
                )
            );

        EffectiveCookieFlagsCheck check =
            new EffectiveCookieFlagsCheck(req -> response);

        ProdGuardContext ctx =
            new MockProdGuardContext()
                .withLocalServerPort(8443);

        CheckResult result =
            check.check(ctx).orElseThrow();

        assertThat(result.message())
            .contains("SameSite=None");
    }

    @Test
    void failsWhenLocalServerPortIsUnavailable() {

        EffectiveCookieFlagsCheck check =
            new EffectiveCookieFlagsCheck(req -> {
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

        EffectiveCookieFlagsCheck check =
            new EffectiveCookieFlagsCheck(req -> {
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
