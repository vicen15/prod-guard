package com.prodguard.checks.free;

import com.prodguard.core.CheckDescriptor;
import com.prodguard.core.ProdCheck;
import com.prodguard.core.Severity;
import org.junit.jupiter.api.Test;
import org.reflections.Reflections;

import java.lang.reflect.Field;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CheckSeverityValidationTest {

    @Test
    void allChecksMustDeclareValidSeverity() throws Exception {
        Reflections reflections = new Reflections("com.prodguard.checks.free");

        Set<Class<? extends ProdCheck>> checkClasses =
                reflections.getSubTypesOf(ProdCheck.class);

        for (Class<? extends ProdCheck> checkClass : checkClasses) {

            Field descriptorField =
                    checkClass.getDeclaredField("DESCRIPTOR");
            descriptorField.setAccessible(true);

            CheckDescriptor descriptor =
                    (CheckDescriptor) descriptorField.get(null);

            Severity severity = descriptor.severity();

            assertNotNull(
                    severity,
                    () -> "Severity must not be null in "
                            + checkClass.getSimpleName()
            );

            assertTrue(
                    severity instanceof Severity,
                    () -> "Invalid severity in "
                            + checkClass.getSimpleName()
            );
        }
    }
}
