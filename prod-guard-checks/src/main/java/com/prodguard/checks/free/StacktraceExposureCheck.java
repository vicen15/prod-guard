package com.prodguard.checks.free;

import com.prodguard.core.*;
import java.util.Optional;

public class StacktraceExposureCheck implements ProdCheck {

    public static final CheckDescriptor DESCRIPTOR =
            new CheckDescriptor(
                    "PG-003",
                    "Error response stacktrace exposure",
                    Severity.ERROR,
                    """
                    Stacktraces in HTTP error responses may expose sensitive internal
                    information such as class names, file paths, or framework details.

                    In production environments, this information can significantly
                    increase the attack surface and aid malicious actors.

                    This check verifies that stacktraces are never included in error
                    responses returned to clients.
                    """                    
            );

    @Override
    public Optional<CheckResult> check(ProdGuardContext ctx) {
        String v = ctx.getProperty("server.error.include-stacktrace").orElse("never");

        if (!"never".equalsIgnoreCase(v)) {
            return Optional.of(new CheckResult(
                    DESCRIPTOR,
                    "Stacktraces are exposed in HTTP error responses",
                    "Configure server.error.include-stacktrace=never"
            ));
        }

        return Optional.empty();
    }
}
