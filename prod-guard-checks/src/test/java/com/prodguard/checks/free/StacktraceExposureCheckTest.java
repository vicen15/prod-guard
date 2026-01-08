package com.prodguard.checks.free;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import com.prodguard.checks.free.StacktraceExposureCheck;
import com.prodguard.checks.support.MockProdGuardContext;

class StacktraceExposureCheckTest {

    private final StacktraceExposureCheck check = new StacktraceExposureCheck();

    @Test
    void failsWhenStacktraceIsExposed() {
        var ctx = new MockProdGuardContext()
                .withProperty("server.error.include-stacktrace", "always");

        var result = check.check(ctx);

        assertTrue(result.isPresent());
        assertEquals("PG-003", result.get().code());
    }

    @Test
    void passesWhenStacktraceIsNever() {
        var ctx = new MockProdGuardContext()
                .withProperty("server.error.include-stacktrace", "never");

        assertTrue(check.check(ctx).isEmpty());
    }
}
