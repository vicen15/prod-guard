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

public class EffectiveCookieFlagsCheck implements ProdCheck {

	public static final CheckDescriptor DESCRIPTOR =
		    new CheckDescriptor(
		        "PG-205",
		        "Effective cookie security flags",
		        Severity.ERROR,
		        """
		        Validates security flags of cookies effectively returned by the
		        application over HTTPS.

		        Cookies used in production must define Secure, HttpOnly and SameSite
		        attributes to mitigate session fixation, XSS and CSRF attacks.

		        This check performs a real HTTPS request against the running
		        application and inspects Set-Cookie headers.
		        """,
		        CheckTier.PREMIUM
		    );

    private final HttpProbe httpProbe;

    // Constructor de producción
    public EffectiveCookieFlagsCheck() {
        HttpClient client =
            HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        this.httpProbe = new JdkHttpProbe(client);
    }

    // Constructor para tests
    EffectiveCookieFlagsCheck(HttpProbe httpProbe) {
        this.httpProbe = httpProbe;
    }
    
    @Override
    public Optional<CheckResult> check(ProdGuardContext ctx) {

        Optional<Integer> portOpt = ctx.getLocalServerPort();
        if (portOpt.isEmpty()) {
            return Optional.of(new CheckResult(
                DESCRIPTOR,
                "Local server port not available",
                "Effective cookie validation requires a running HTTPS port"
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

            List<String> cookies =
                response.headers().allValues("Set-Cookie");

            if (cookies.isEmpty()) {
                return Optional.empty();
            }

            for (String cookie : cookies) {
                String lower = cookie.toLowerCase(Locale.ROOT);

                boolean secure = lower.contains("secure");
                boolean httpOnly = lower.contains("httponly");
                boolean sameSite = lower.contains("samesite");

                if (!secure) {
                    return Optional.of(new CheckResult(
                        DESCRIPTOR,
                        "Cookie is missing Secure flag: " + cookie,
                        "Add the Secure attribute to cookies sent over HTTPS"
                    ));
                }

                if (!httpOnly) {
                    return Optional.of(new CheckResult(
                        DESCRIPTOR,
                        "Cookie is missing HttpOnly flag: " + cookie,
                        "Add the HttpOnly attribute to prevent JavaScript access"
                    ));
                }

                if (!sameSite) {
                    return Optional.of(new CheckResult(
                        DESCRIPTOR,
                        "Cookie is missing SameSite attribute: " + cookie,
                        "Define SameSite=Strict or SameSite=Lax for cookies"
                    ));
                }

                if (lower.contains("samesite=none") && !secure) {
                    return Optional.of(new CheckResult(
                        DESCRIPTOR,
                        "Cookie uses SameSite=None without Secure: " + cookie,
                        "SameSite=None cookies must also define Secure"
                    ));
                }
            }

            return Optional.empty();

        } catch (Exception e) {
            return Optional.of(new CheckResult(
                DESCRIPTOR,
                "Failed to perform HTTPS request: " + e.getMessage(),
                "Ensure the application is reachable over HTTPS during startup"
            ));
        }
    }
}
