package com.prodguard.core;

public record CheckDescriptor(String code, String name, Severity severity, String longDescription, CheckTier tier) {
	
	public CheckDescriptor(String code, String name, Severity severity) {
		this(code, name, severity, null, CheckTier.CORE);
	}

    // Constructor con tier
    public CheckDescriptor(String code,
                           String name,
                           Severity severity,
                           CheckTier tier) {
        this(code, name, severity, null, tier);
    }	
	
	public boolean hasLongDescription() {
		return longDescription != null && !longDescription.isBlank();
	}
	
    // Constructor con descripción larga (CORE por defecto)
    public CheckDescriptor(String code,
                           String name,
                           Severity severity,
                           String longDescription) {
        this(code, name, severity, longDescription, CheckTier.CORE);
    }	
	
}