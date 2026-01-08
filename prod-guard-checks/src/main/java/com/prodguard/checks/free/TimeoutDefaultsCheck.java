package com.prodguard.checks.free;

import com.prodguard.core.*;
import java.util.Optional;

public class TimeoutDefaultsCheck implements ProdCheck {

    public static final CheckDescriptor DESCRIPTOR =
            new CheckDescriptor(
                    "PG-010",
                    "HTTP request timeout configuration",
                    Severity.WARN
            );

    @Override
    public Optional<CheckResult> check(ProdGuardContext ctx) {
        Optional<String> timeout =
                ctx.getProperty("spring.mvc.async.request-timeout");

        if (timeout.isEmpty()) {
            return Optional.of(new CheckResult(
                    DESCRIPTOR,
                    "HTTP request timeout is not configured (spring.mvc.async.request-timeout)",
                    "Configure explicit request timeouts for production workloads"
            ));
        }

        return Optional.empty();
    }
}
