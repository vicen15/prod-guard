package com.prodguard.checks.premium.security;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import com.prodguard.core.CheckDescriptor;
import com.prodguard.core.CheckResult;
import com.prodguard.core.CheckTier;
import com.prodguard.core.ProdCheck;
import com.prodguard.core.ProdGuardContext;
import com.prodguard.core.Severity;

public class EffectiveCrossOriginOpenerPolicyCheck implements ProdCheck {

    public static final CheckDescriptor DESCRIPTOR =
        new CheckDescriptor(
            "PG-209",
            "Effective Cross-Origin-Opener-Policy header",
            Severity.WARN,
            """
            Validates the effective Cross-Origin-Opener-Policy (COOP) header
            by performing a real HTTPS request against the running application.

            Missing or weak COOP policies may expose the application to
            cross-origin attacks such as XS-Leaks or Spectre-based data leaks.
            """,
            CheckTier.PREMIUM
        );

    private static final Set<String> SAFE_POLICIES = Set.of(
        "same-origin",
        "same-origin-allow-popups"
    );

    private final HttpProbe httpProbe;

    /**
     * Production constructor
     */
    public EffectiveCrossOriginOpenerPolicyCheck() {
        HttpClient client =
            HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        this.httpProbe = new JdkHttpProbe(client);
    }

    /**
     * Test / injection constructor
     */
    public EffectiveCrossOriginOpenerPolicyCheck(HttpProbe httpProbe) {
        this.httpProbe = httpProbe;
    }

    @Override
    public Optional<CheckResult> check(ProdGuardContext ctx) {

        Optional<Integer> portOpt = ctx.getLocalServerPort();
        if (portOpt.isEmpty()) {
            return Optional.of(CheckResult.error(
                DESCRIPTOR,
                "Local server port is not available",
                "Ensure the application is running before executing effective checks"
            ));
        }

        try {
            URI uri = URI.create("https://localhost:" + portOpt.get() + "/");

            HttpRequest request =
                HttpRequest.newBuilder(uri)
                    .GET()
                    .build();

            HttpResponse<Void> response =
                httpProbe.send(request);

            List<String> values =
                response.headers().allValues("Cross-Origin-Opener-Policy");

            if (values.isEmpty()) {
                return Optional.of(CheckResult.warn(
                    DESCRIPTOR,
                    "Cross-Origin-Opener-Policy header is not present",
                    "Configure COOP to isolate the browsing context"
                ));
            }

            String policy =
                values.get(0).toLowerCase();

            if (!SAFE_POLICIES.contains(policy)) {
                return Optional.of(CheckResult.warn(
                    DESCRIPTOR,
                    "Weak Cross-Origin-Opener-Policy detected: " + policy,
                    "Use one of: " + SAFE_POLICIES
                ));
            }

            return Optional.empty();

        } catch (Exception ex) {
            return Optional.of(CheckResult.error(
                DESCRIPTOR,
                "Failed to perform HTTPS request",
                ex.getMessage()
            ));
        }
    }
}
