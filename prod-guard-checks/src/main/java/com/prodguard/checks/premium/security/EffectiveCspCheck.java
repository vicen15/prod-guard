package com.prodguard.checks.premium.security;

import com.prodguard.core.CheckDescriptor;
import com.prodguard.core.CheckResult;
import com.prodguard.core.CheckTier;
import com.prodguard.core.ProdCheck;
import com.prodguard.core.ProdGuardContext;
import com.prodguard.core.Severity;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class EffectiveCspCheck implements ProdCheck {

    public static final CheckDescriptor DESCRIPTOR =
        new CheckDescriptor(
            "PG-204",
            "Effective Content Security Policy",
            Severity.ERROR,
            """
            Validates the effective Content-Security-Policy (CSP) header
            returned by the application at runtime.

            This check ensures that CSP is enforced (not report-only) and
            does not include insecure directives such as unsafe-inline,
            unsafe-eval, or wildcard sources.
            """,
            CheckTier.PREMIUM
        );

    private final HttpProbe httpProbe;

    // Constructor público (producción)
    public EffectiveCspCheck() {
        HttpClient client =
            HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        this.httpProbe = new JdkHttpProbe(client);
    }

    // Constructor package-private (tests)
    EffectiveCspCheck(HttpProbe httpProbe) {
        this.httpProbe = httpProbe;
    }

    @Override
    public Optional<CheckResult> check(ProdGuardContext ctx) {

        Optional<Integer> portOpt = ctx.getLocalServerPort();
        if (portOpt.isEmpty()) {
            return Optional.of(new CheckResult(
                DESCRIPTOR,
                "Unable to determine local server port for CSP validation",
                "Ensure the application is running as a web server"
            ));
        }

        int port = portOpt.get();

        HttpRequest request =
            HttpRequest.newBuilder()
                .uri(URI.create("https://localhost:" + port + "/"))
                .timeout(Duration.ofSeconds(5))
                .GET()
                .build();

        HttpResponse<Void> response;

        try {
            response = httpProbe.send(request);
        } catch (Exception e) {
            return Optional.of(new CheckResult(
                DESCRIPTOR,
                "Failed to perform HTTPS request for CSP inspection",
                "Verify HTTPS connectivity and TLS configuration"
            ));
        }

        Map<String, List<String>> headers =
            normalizeHeaders(response.headers().map());

        if (headers.containsKey("content-security-policy-report-only")) {
            return Optional.of(new CheckResult(
                DESCRIPTOR,
                "CSP is configured in report-only mode",
                "Enforce Content-Security-Policy instead of report-only"
            ));
        }

        List<String> values = headers.get("content-security-policy");

        if (values == null || values.isEmpty()) {
            return Optional.of(new CheckResult(
                DESCRIPTOR,
                "Content-Security-Policy header is not present",
                "Define a strict Content-Security-Policy for production"
            ));
        }

        String csp = values.get(0).toLowerCase();

        if (csp.contains("unsafe-inline") || csp.contains("unsafe-eval")) {
            return Optional.of(new CheckResult(
                DESCRIPTOR,
                "CSP contains unsafe directives (unsafe-inline / unsafe-eval)",
                "Remove unsafe CSP directives and use nonces or hashes"
            ));
        }

        if (cspAllowsWildcard(csp)) {
            return Optional.of(new CheckResult(
                DESCRIPTOR,
                "CSP allows wildcard sources",
                "Restrict CSP sources explicitly instead of using '*'"
            ));
        }

        return Optional.empty();
    }

    private static boolean cspAllowsWildcard(String csp) {
        for (String directive : csp.split(";")) {
            directive = directive.trim();
            if (directive.startsWith("default-src") && directive.contains("*")) {
                return true;
            }
        }
        return false;
    }

    private static Map<String, List<String>> normalizeHeaders(
            Map<String, List<String>> rawHeaders) {

        return rawHeaders.entrySet().stream()
            .collect(
                java.util.stream.Collectors.toMap(
                    e -> e.getKey().toLowerCase(),
                    Map.Entry::getValue
                )
            );
    }
}
