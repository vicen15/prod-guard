package com.prodguard.checks.free;

import com.prodguard.checks.free.DebugLoggingCheck;
import com.prodguard.checks.support.MockProdGuardContext;
import com.prodguard.core.CheckResult;
import com.prodguard.core.Severity;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class DebugLoggingCheckTest {

    private final DebugLoggingCheck check = new DebugLoggingCheck();

    @Test
    void returnsErrorWhenRootLoggingIsDebug() {
        var ctx = new MockProdGuardContext()
                .withProperty("logging.level.root", "DEBUG");

        Optional<CheckResult> result = check.check(ctx);

        assertTrue(result.isPresent());
        assertEquals(Severity.ERROR, result.get().severity());
        assertEquals("PG-001", result.get().code());
    }

    @Test
    void returnsEmptyWhenLoggingIsInfo() {
        var ctx = new MockProdGuardContext()
                .withProperty("logging.level.root", "INFO");

        Optional<CheckResult> result = check.check(ctx);

        assertTrue(result.isEmpty());
    }
}
