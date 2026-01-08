package com.prodguard.checks.free;

import com.prodguard.core.*;
import java.util.Optional;

public class HttpsEnabledCheck implements ProdCheck {

    public static final CheckDescriptor DESCRIPTOR =
            new CheckDescriptor(
                    "PG-005",
                    "HTTPS / TLS configuration",
                    Severity.ERROR
            );

    @Override
    public Optional<CheckResult> check(ProdGuardContext ctx) {
        String v = ctx.getProperty("server.ssl.enabled").orElse("false");

        if (!"true".equalsIgnoreCase(v)) {
            return Optional.of(new CheckResult(
                    DESCRIPTOR,
                    "HTTPS is not enabled (server.ssl.enabled is not set to true)",
                    "Enable TLS/SSL for production by configuring server.ssl.* properties"
            ));
        }

        return Optional.empty();
    }
}
