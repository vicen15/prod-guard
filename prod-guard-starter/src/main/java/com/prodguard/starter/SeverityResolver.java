package com.prodguard.starter;

import com.prodguard.core.CheckResult;
import com.prodguard.core.EffectiveSeverity;
import com.prodguard.core.Severity;

public class SeverityResolver {

    private final ProdGuardProperties properties;

    public SeverityResolver(ProdGuardProperties properties) {
        this.properties = properties;
    }

    public EffectiveSeverity resolve(CheckResult result) {
        return properties.getSeverities()
                .getOrDefault(
                    result.code(),
                    mapDefault(result.severity())
                );
    }

    private EffectiveSeverity mapDefault(Severity severity) {
        return switch (severity) {
            case INFO -> EffectiveSeverity.INFO;
            case WARN -> EffectiveSeverity.WARN;
            case ERROR -> EffectiveSeverity.ERROR;
        };
    }
}
