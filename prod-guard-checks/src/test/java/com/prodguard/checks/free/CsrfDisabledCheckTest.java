package com.prodguard.checks.free;

import com.prodguard.checks.free.CsrfDisabledCheck;
import com.prodguard.checks.support.MockProdGuardContext;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CsrfDisabledCheckTest {

    private final CsrfDisabledCheck check = new CsrfDisabledCheck();

    @Test
    void alwaysReturnsWarning() {
        var ctx = new MockProdGuardContext();

        var result = check.check(ctx);

        assertTrue(result.isPresent());
        assertEquals("PG-007", result.get().code());
    }
}
