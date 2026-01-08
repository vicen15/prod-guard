package com.prodguard.checks.free;

import com.prodguard.checks.free.HttpsEnabledCheck;
import com.prodguard.checks.support.MockProdGuardContext;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class HttpsEnabledCheckTest {

    private final HttpsEnabledCheck check = new HttpsEnabledCheck();

    @Test
    void failsWhenHttpsIsDisabled() {
        var ctx = new MockProdGuardContext()
                .withProperty("server.ssl.enabled", "false");

        var result = check.check(ctx);

        assertTrue(result.isPresent());
        assertEquals("PG-005", result.get().code());
    }

    @Test
    void passesWhenHttpsIsEnabled() {
        var ctx = new MockProdGuardContext()
                .withProperty("server.ssl.enabled", "true");

        assertTrue(check.check(ctx).isEmpty());
    }
}
