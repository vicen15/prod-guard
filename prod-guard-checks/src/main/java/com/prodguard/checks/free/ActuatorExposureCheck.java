package com.prodguard.checks.free;

import com.prodguard.core.*;
import java.util.Optional;

public class ActuatorExposureCheck implements ProdCheck {

    public static final CheckDescriptor DESCRIPTOR =
            new CheckDescriptor(
                    "PG-004",
                    "Spring Boot Actuator endpoint exposure",
                    Severity.WARN);	

	
    @Override
    public Optional<CheckResult> check(ProdGuardContext ctx) {
        String exposed = ctx.getProperty("management.endpoints.web.exposure.include").orElse("");
        if (exposed.contains("*")) {
            return Optional.of(new CheckResult(
            		DESCRIPTOR,
                    "All actuator endpoints are publicly exposed ('*')",
                    "Restrict actuator exposure (management.endpoints.web.exposure.include)"
            ));
        }
        return Optional.empty();
    }
}