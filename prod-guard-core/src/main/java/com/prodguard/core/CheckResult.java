package com.prodguard.core;

public record CheckResult(
        CheckDescriptor descriptor,
        String message,
        String remediation
) {
    public String code() {
        return descriptor.code();
    }

    public Severity severity() {
        return descriptor.severity();
    }
    
    public static CheckResult warn(
            CheckDescriptor descriptor,
            String message,
            String remediation
        ) {
            return new CheckResult(descriptor, message, remediation);
        }

    public static CheckResult error(
            CheckDescriptor descriptor,
            String message,
            String remediation
        ) {
            return new CheckResult(descriptor, message, remediation);
        }    
}
