package com.prodguard.checks.free;

import com.prodguard.core.*;
import java.util.Optional;

public class CsrfDisabledCheck implements ProdCheck {

    public static final CheckDescriptor DESCRIPTOR =
            new CheckDescriptor(
                    "PG-007",
                    "CSRF protection configuration review",
                    Severity.WARN);	
                    
	
    @Override
    public Optional<CheckResult> check(ProdGuardContext ctx) {
        // We conservatively warn: detecting CSRF programmatically is framework-specific.
        return Optional.of(new CheckResult(
        		DESCRIPTOR,
        		"CSRF protection should be reviewed for publicly exposed endpoints",
                "Verify CSRF is enabled where applicable (APIs may disable it with care)"
        ));
    }
}