package com.prodguard.checks.free;

import com.prodguard.core.*;
import java.util.Optional;

public class SecurityHeadersCheck implements ProdCheck {

    public static final CheckDescriptor DESCRIPTOR =
            new CheckDescriptor(
                    "PG-006",
                    "HTTP security headers infrastructure",
                    Severity.WARN
            );

    @Override
    public Optional<CheckResult> check(ProdGuardContext ctx) {
        boolean hasSecurity =
                ctx.hasBean("org.springframework.security.web.SecurityFilterChain");

        if (!hasSecurity) {
            return Optional.of(new CheckResult(
                    DESCRIPTOR,
                    "Spring Security was not detected (no SecurityFilterChain bean found)",
                    "Add Spring Security or ensure equivalent security headers are configured"
            ));
        }

        return Optional.empty();
    }
}
