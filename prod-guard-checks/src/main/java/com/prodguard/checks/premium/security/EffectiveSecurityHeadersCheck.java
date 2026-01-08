package com.prodguard.checks.premium.security;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.prodguard.core.CheckDescriptor;
import com.prodguard.core.CheckResult;
import com.prodguard.core.CheckTier;
import com.prodguard.core.ProdCheck;
import com.prodguard.core.ProdGuardContext;
import com.prodguard.core.Severity;

public class EffectiveSecurityHeadersCheck implements ProdCheck {

    public static final CheckDescriptor DESCRIPTOR =
        new CheckDescriptor(
            "PG-201",
            "Effective HTTP security headers",
            Severity.ERROR,
            """
            Validates the effective HTTP security headers returned by the
            application at runtime.

            This check performs a real HTTP request against the local server
            to ensure that critical security headers are present and correctly
            configured, accounting for filters, proxies, and runtime overrides.
            """,
            CheckTier.PREMIUM
        );
    
    private static final List<String> REQUIRED_HEADERS = List.of(
            "x-content-type-options",
            "x-frame-options"
        );

        private static final List<String> RECOMMENDED_HEADERS = List.of(
            "content-security-policy",
            "referrer-policy"
        );

        @Override
        public Optional<CheckResult> check(ProdGuardContext ctx) {

            Optional<Integer> portOpt = ctx.getLocalServerPort();
            if (portOpt.isEmpty()) {
                return Optional.of(new CheckResult(
                    DESCRIPTOR,
                    "Unable to determine local server port for HTTP inspection",
                    "Ensure the application is running as a web server"
                ));
            }

            int port = portOpt.get();

            HttpClient client =
                HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(3))
                    .build();

            HttpRequest request =
                HttpRequest.newBuilder()
                    .uri(URI.create("http://localhost:" + port + "/actuator/health"))
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build();

            HttpResponse<Void> response;

            try {
                response =
                    client.send(
                        request,
                        HttpResponse.BodyHandlers.discarding()
                    );
            } catch (Exception e) {
                return Optional.of(new CheckResult(
                    DESCRIPTOR,
                    "Failed to perform HTTP request for header inspection",
                    "Verify the server is reachable and actuator is enabled"
                ));
            }

            Map<String, List<String>> headers =
                normalizeHeaders(response.headers().map());

            List<String> missingRequired = new ArrayList<>();
            List<String> missingRecommended = new ArrayList<>();

            for (String h : REQUIRED_HEADERS) {
                if (!headers.containsKey(h)) {
                    missingRequired.add(h);
                }
            }

            for (String h : RECOMMENDED_HEADERS) {
                if (!headers.containsKey(h)) {
                    missingRecommended.add(h);
                }
            }

            if (!missingRequired.isEmpty()) {
                return Optional.of(new CheckResult(
                    DESCRIPTOR,
                    "Missing required HTTP security headers: " +
                        String.join(", ", missingRequired),
                    "Configure HttpSecurity.headers() or verify reverse proxy configuration"
                ));
            }

            if (!missingRecommended.isEmpty()) {
                return Optional.of(new CheckResult(
                    DESCRIPTOR,
                    "Missing recommended HTTP security headers: " +
                        String.join(", ", missingRecommended),
                    "Consider hardening security headers for production environments"
                ));
            }

            return Optional.empty();
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
        }}
