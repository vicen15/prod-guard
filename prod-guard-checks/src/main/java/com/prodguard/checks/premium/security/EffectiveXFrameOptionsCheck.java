package com.prodguard.checks.premium.security;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import com.prodguard.core.CheckDescriptor;
import com.prodguard.core.CheckResult;
import com.prodguard.core.CheckTier;
import com.prodguard.core.ProdCheck;
import com.prodguard.core.ProdGuardContext;
import com.prodguard.core.Severity;

public class EffectiveXFrameOptionsCheck implements ProdCheck {

	public static final CheckDescriptor DESCRIPTOR =
		    new CheckDescriptor(
		        "PG-206",
		        "Effective clickjacking protection",
		        Severity.ERROR,
		        """
		        Validates that the application effectively protects against
		        clickjacking attacks by preventing rendering inside iframes.

		        Protection is verified by inspecting HTTP response headers
		        returned over HTTPS, including X-Frame-Options and
		        Content-Security-Policy frame-ancestors directives.
		        """,
		        CheckTier.PREMIUM
		        
		    );

    private final HttpProbe httpProbe;

    // Constructor de producción
    public EffectiveXFrameOptionsCheck() {

        HttpClient client =
            HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        this.httpProbe = new JdkHttpProbe(client);
    }

    // Constructor para tests
    EffectiveXFrameOptionsCheck(HttpProbe httpProbe) {
        this.httpProbe = httpProbe;
    }

    @Override
    public Optional<CheckResult> check(ProdGuardContext ctx) {

        Optional<Integer> portOpt = ctx.getLocalServerPort();
        if (portOpt.isEmpty()) {
            return Optional.of(new CheckResult(
                DESCRIPTOR,
                "Local server port not available",
                "Clickjacking protection requires a running HTTPS port"
            ));
        }

        int port = portOpt.get();

        try {
            HttpRequest request =
                HttpRequest.newBuilder()
                    .uri(URI.create("https://localhost:" + port + "/"))
                    .GET()
                    .build();

            HttpResponse<Void> response = httpProbe.send(request);

            List<String> xfo =
                response.headers().allValues("X-Frame-Options");

            if (!xfo.isEmpty()) {
                String value = xfo.get(0).toLowerCase(Locale.ROOT);

                if (value.contains("deny") || value.contains("sameorigin")) {
                    return Optional.empty();
                }

                return Optional.of(new CheckResult(
                    DESCRIPTOR,
                    "Invalid X-Frame-Options value: " + xfo.get(0),
                    "Use X-Frame-Options DENY or SAMEORIGIN"
                ));
            }

            // Fallback moderno: CSP frame-ancestors
            List<String> csp =
                response.headers().allValues("Content-Security-Policy");

            if (!csp.isEmpty()) {
                String policy = csp.get(0).toLowerCase(Locale.ROOT);
                if (policy.contains("frame-ancestors")) {
                    return Optional.empty();
                }
            }

            return Optional.of(new CheckResult(
                DESCRIPTOR,
                "No clickjacking protection detected",
                "Configure X-Frame-Options or CSP frame-ancestors"
            ));

        } catch (Exception e) {
            return Optional.of(new CheckResult(
                DESCRIPTOR,
                "Failed to perform HTTPS request: " + e.getMessage(),
                "Ensure the application is reachable over HTTPS during startup"
            ));
        }
    }
}
