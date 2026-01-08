package com.prodguard.checks.free;

import com.prodguard.core.*;
import java.util.Optional;

public class ShowSqlCheck implements ProdCheck {

    public static final CheckDescriptor DESCRIPTOR =
            new CheckDescriptor(
                    "PG-002",
                    "JPA SQL logging configuration",
                    Severity.WARN
            );

    @Override
    public Optional<CheckResult> check(ProdGuardContext ctx) {
        String v = ctx.getProperty("spring.jpa.show-sql").orElse("false");

        if ("true".equalsIgnoreCase(v)) {
            return Optional.of(new CheckResult(
                    DESCRIPTOR,
                    "JPA SQL logging is enabled (spring.jpa.show-sql=true)",
                    "Disable spring.jpa.show-sql in production environments"
            ));
        }

        return Optional.empty();
    }
}
