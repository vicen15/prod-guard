package com.prodguard.checks.free;

import java.util.Optional;

import com.prodguard.core.CheckDescriptor;
import com.prodguard.core.CheckResult;
import com.prodguard.core.ProdCheck;
import com.prodguard.core.ProdGuardContext;
import com.prodguard.core.Severity;

public class CorsWildcardCheck implements ProdCheck {

    public static final CheckDescriptor DESCRIPTOR =
            new CheckDescriptor(
                    "PG-013",
                    "CORS configuration scope",
                    Severity.WARN,
                    """
                    Permissive CORS configurations using wildcard origins may
                    allow unintended cross-origin access to APIs.

                    Production environments should explicitly restrict allowed
                    origins whenever possible.
                    """
            );

    @Override
    public Optional<CheckResult> check(ProdGuardContext ctx) {
        String origins =
                ctx.getProperty("spring.web.cors.allowed-origins").orElse("");

        if (origins.contains("*")) {
            return Optional.of(new CheckResult(
                    DESCRIPTOR,
                    "CORS allows all origins ('*')",
                    "Restrict spring.web.cors.allowed-origins to trusted domains"
            ));
        }

        return Optional.empty();
    }
}
