package com.prodguard.checks.free;

import java.util.Optional;

import com.prodguard.core.CheckDescriptor;
import com.prodguard.core.CheckResult;
import com.prodguard.core.ProdCheck;
import com.prodguard.core.ProdGuardContext;
import com.prodguard.core.Severity;

public class OpenInViewCheck implements ProdCheck {

    public static final CheckDescriptor DESCRIPTOR =
            new CheckDescriptor(
                    "PG-011",
                    "JPA Open Session In View configuration",
                    Severity.WARN,
                    """
                    The Open Session In View (OSIV) pattern keeps the persistence
                    context open during the entire web request.

                    While convenient during development, it can hide performance
                    issues and lead to N+1 query problems in production.
                    """
            );

    @Override
    public Optional<CheckResult> check(ProdGuardContext ctx) {
        boolean osivEnabled =
                ctx.getProperty("spring.jpa.open-in-view")
                   .map(Boolean::parseBoolean)
                   .orElse(true); // <-- DEFAULT REAL

        if (osivEnabled) {
            return Optional.of(new CheckResult(
                    DESCRIPTOR,
                    "JPA Open Session In View is enabled",
                    "Set spring.jpa.open-in-view=false"
            ));
        }

        return Optional.empty();
    }}
