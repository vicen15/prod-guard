package com.prodguard.checks.free;

import com.prodguard.core.*;
import java.util.Optional;

public class HeapSizeCheck implements ProdCheck {

	public static final CheckDescriptor DESCRIPTOR =
	        new CheckDescriptor(
	                "PG-008",
	                "JVM maximum heap size configuration",
	                Severity.WARN
	        );

	
    @Override
    public Optional<CheckResult> check(ProdGuardContext ctx) {
        long maxHeapMb = Runtime.getRuntime().maxMemory() / (1024L * 1024L);
        if (maxHeapMb < 512) {
            return Optional.of(new CheckResult(
            		DESCRIPTOR,
            		 "Maximum JVM heap size is below 512 MB (" + maxHeapMb + " MB detected)",
            	     "Increase the JVM -Xmx setting for production workloads"
            ));
        }
        return Optional.empty();
    }
}