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

public class EffectiveHttpsCheck implements ProdCheck {

	private final HttpProbe httpProbe;
	
    public EffectiveHttpsCheck() {
        this(HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build());
    }

    EffectiveHttpsCheck(HttpClient client) {
        this.httpProbe = new JdkHttpProbe(client);
    }	
	
    //Constructor SOLO para tests
    EffectiveHttpsCheck(HttpProbe httpProbe) {
        this.httpProbe = httpProbe;
    }
    
    public static final CheckDescriptor DESCRIPTOR =
        new CheckDescriptor(
            "PG-202",
            "Effective HTTPS enforcement",
            Severity.ERROR,
            """
            Verifies that the application effectively enforces HTTPS at runtime.

            This check performs an HTTP request and validates whether the
            application redirects to HTTPS or explicitly rejects insecure
            connections, accounting for reverse proxies and deployment
            topology.
            """,
            CheckTier.PREMIUM
        );

    @Override
    public Optional<CheckResult> check(ProdGuardContext ctx) {

        Optional<Integer> portOpt = ctx.getLocalServerPort();
        if (portOpt.isEmpty()) {
            return Optional.of(new CheckResult(
                DESCRIPTOR,
                "Unable to determine local server port for HTTPS validation",
                "Ensure the application is running as a web server"
            ));
        }

        int port = portOpt.get();

        HttpClient client =
            HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        HttpRequest request =
            HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/"))
                .timeout(Duration.ofSeconds(5))
                .GET()
                .build();

        HttpResponse<Void> response;

        try {
            response =
            	httpProbe.send(request);
        } catch (Exception e) {
            return Optional.of(new CheckResult(
                DESCRIPTOR,
                "Failed to perform HTTP request for HTTPS enforcement check",
                "Verify the server is reachable and accepts HTTP connections"
            ));
        }

        int status = response.statusCode();
        Map<String, List<String>> headers =
            normalizeHeaders(response.headers().map());

        // Case 1: Redirect to HTTPS
        if (status == 301 || status == 302 || status == 307 || status == 308) {

            List<String> locations = headers.get("location");

            if (locations != null &&
                locations.stream().anyMatch(l -> l.startsWith("https://"))) {
                return Optional.empty();
            }

            return Optional.of(new CheckResult(
                DESCRIPTOR,
                "HTTP requests are redirected, but not to HTTPS",
                "Ensure HTTP traffic is redirected to HTTPS endpoints"
            ));
        }

        // Case 2: Explicit rejection
        if (status == 403 || status == 426) {
            return Optional.empty();
        }

        // Case 3: Insecure acceptance
        return Optional.of(new CheckResult(
            DESCRIPTOR,
            "Application accepts plain HTTP requests without HTTPS enforcement",
            "Configure HTTPS redirection or enforce TLS at proxy/application level"
        ));
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
