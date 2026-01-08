package com.prodguard.checks.free;

import java.util.Optional;

import com.prodguard.core.CheckDescriptor;
import com.prodguard.core.CheckResult;
import com.prodguard.core.ProdCheck;
import com.prodguard.core.ProdGuardContext;
import com.prodguard.core.Severity;

public class GracefulShutdownCheck implements ProdCheck {

    public static final CheckDescriptor DESCRIPTOR =
            new CheckDescriptor(
                    "PG-012",
                    "Graceful shutdown configuration",
                    Severity.WARN,
                    """
                    Graceful shutdown allows in-flight HTTP requests to complete
                    before the application stops.

                    Without it, deployments may abruptly terminate active
                    connections, causing errors for clients.
                    """
            );

    @Override
    public Optional<CheckResult> check(ProdGuardContext ctx) {
        String v = ctx.getProperty("server.shutdown").orElse("immediate");

        if (!"graceful".equalsIgnoreCase(v)) {
            return Optional.of(new CheckResult(
                    DESCRIPTOR,
                    "Graceful shutdown is not enabled",
                    "Set server.shutdown=graceful for production deployments"
            ));
        }

        return Optional.empty();
    }
}
