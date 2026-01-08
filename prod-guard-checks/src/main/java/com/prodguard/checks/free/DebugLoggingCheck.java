package com.prodguard.checks.free;

import com.prodguard.core.*;
import java.util.Optional;

public class DebugLoggingCheck implements ProdCheck {

    public static final CheckDescriptor DESCRIPTOR =
            new CheckDescriptor(
                    "PG-001",
                    "Root logging level configuration",
                    Severity.ERROR
            );
	
    @Override
    public Optional<CheckResult> check(ProdGuardContext ctx) {
        String level = ctx.getProperty("logging.level.root").orElse("INFO");
        if ("DEBUG".equalsIgnoreCase(level)) {
            return Optional.of(new CheckResult(
            		DESCRIPTOR,
                    "Root logging level is DEBUG",
                    "Set logging.level.root=INFO or WARN"
            ));
        }
        return Optional.empty();
    }
}