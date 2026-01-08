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

public class EffectiveHstsCheck implements ProdCheck {

    public static final CheckDescriptor DESCRIPTOR =
        new CheckDescriptor(
            "PG-203",
            "Effective HSTS configuration",
            Severity.ERROR,
            """
            Verifies that the application effectively enforces HTTP Strict
            Transport Security (HSTS) at runtime.

            This check validates the presence and strength of the
            Strict-Transport-Security header returned by the application,
            accounting for reverse proxies and deployment topology.
            """,
            CheckTier.PREMIUM
        );

    private final HttpProbe httpProbe;

    // Constructor público (producción)
    public EffectiveHstsCheck() {
        HttpClient client =
            HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        this.httpProbe = new JdkHttpProbe(client);
    }

    // Constructor package-private (tests)
    EffectiveHstsCheck(HttpProbe httpProbe) {
        this.httpProbe = httpProbe;
    }

    @Override
    public Optional<CheckResult> check(ProdGuardContext ctx) {

        Optional<Integer> portOpt = ctx.getLocalServerPort();
        if (portOpt.isEmpty()) {
            return Optional.of(new CheckResult(
                DESCRIPTOR,
                "Unable to determine local server port for HSTS validation",
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
                "Failed to perform HTTPS request for HSTS inspection",
                "Verify HTTPS connectivity and TLS configuration"
            ));
        }

        Map<String, List<String>> headers =
            normalizeHeaders(response.headers().map());

        List<String> hstsValues = headers.get("strict-transport-security");

        if (hstsValues == null || hstsValues.isEmpty()) {
            return Optional.of(new CheckResult(
                DESCRIPTOR,
                "HSTS header is not present in HTTPS responses",
                "Configure Strict-Transport-Security with an appropriate max-age"
            ));
        }

        String hsts = hstsValues.get(0).toLowerCase();

        if (!hsts.contains("max-age=")) {
            return Optional.of(new CheckResult(
                DESCRIPTOR,
                "HSTS header is present but missing max-age directive",
                "Configure Strict-Transport-Security with a valid max-age"
            ));
        }

        long maxAge = parseMaxAge(hsts);

        if (maxAge < 31536000) { // 1 year
            return Optional.of(new CheckResult(
                DESCRIPTOR,
                "HSTS max-age is too low (" + maxAge + " seconds)",
                "Use a max-age of at least 31536000 seconds (1 year)"
            ));
        }

        return Optional.empty();
    }

    private static long parseMaxAge(String hsts) {
        try {
            for (String part : hsts.split(";")) {
                part = part.trim();
                if (part.startsWith("max-age=")) {
                    return Long.parseLong(part.substring("max-age=".length()));
                }
            }
        } catch (Exception ignored) {
        }
        return -1;
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
