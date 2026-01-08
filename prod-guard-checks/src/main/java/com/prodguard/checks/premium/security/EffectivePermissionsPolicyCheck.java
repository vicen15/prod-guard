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

public class EffectivePermissionsPolicyCheck implements ProdCheck {

    public static final CheckDescriptor DESCRIPTOR =
        new CheckDescriptor(
            "PG-208",
            "Effective Permissions-Policy header",
            Severity.WARN,
            """
            Validates the effective Permissions-Policy header by performing
            a real HTTPS request against the running application.

            Missing or permissive permissions policies may allow browser
            features such as camera, microphone, or geolocation to be
            accessed unexpectedly.
            """,
            CheckTier.PREMIUM
        );

    private static final Set<String> SENSITIVE_FEATURES = Set.of(
        "camera",
        "microphone",
        "geolocation",
        "payment",
        "usb",
        "serial",
        "bluetooth"
    );

    private final HttpProbe httpProbe;

    /**
     * Production constructor
     */
    public EffectivePermissionsPolicyCheck() {
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
    public EffectivePermissionsPolicyCheck(HttpProbe httpProbe) {
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
                response.headers().allValues("Permissions-Policy");

            if (values.isEmpty()) {
                return Optional.of(CheckResult.warn(
                    DESCRIPTOR,
                    "Permissions-Policy header is not present",
                    "Configure a restrictive Permissions-Policy"
                ));
            }

            String policy =
                values.get(0).toLowerCase();

            for (String feature : SENSITIVE_FEATURES) {
                if (policy.contains(feature + "=*")) {
                    return Optional.of(CheckResult.warn(
                        DESCRIPTOR,
                        "Unrestricted browser feature detected: " + feature,
                        "Restrict " + feature + " in Permissions-Policy"
                    ));
                }
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
