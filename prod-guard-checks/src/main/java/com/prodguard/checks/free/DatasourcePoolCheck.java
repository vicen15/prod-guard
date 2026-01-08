package com.prodguard.checks.free;

import com.prodguard.core.*;
import java.util.Optional;

public class DatasourcePoolCheck implements ProdCheck {

    public static final CheckDescriptor DESCRIPTOR =
            new CheckDescriptor(
                    "PG-009",
                    "Datasource pool size configuration",
                    Severity.WARN
            );
	
    @Override
    public Optional<CheckResult> check(ProdGuardContext ctx) {
        Optional<String> pool = ctx.getProperty("spring.datasource.hikari.maximum-pool-size");
        if (pool.isEmpty()) {
            return Optional.of(new CheckResult(
                    DESCRIPTOR,
                    "Datasource pool size not configured (spring.datasource.hikari.maximum-pool-size)",
                    "Explicitly configure connection pool size for production"
            ));
        }
        return Optional.empty();
    }
}