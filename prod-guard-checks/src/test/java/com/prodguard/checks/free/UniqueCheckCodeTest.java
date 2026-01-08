package com.prodguard.checks.free;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.reflections.Reflections;

import com.prodguard.core.CheckDescriptor;
import com.prodguard.core.ProdCheck;

public class UniqueCheckCodeTest {

    @Test
    void allCheckCodesMustBeUnique() throws Exception {
        Reflections reflections = new Reflections("com.prodguard.checks.free");

        Set<Class<? extends ProdCheck>> checkClasses =
                reflections.getSubTypesOf(ProdCheck.class);

        Set<String> seenCodes = new HashSet<>();

        for (Class<? extends ProdCheck> checkClass : checkClasses) {

            Field descriptorField = checkClass.getDeclaredField("DESCRIPTOR");

            assertTrue(
                    CheckDescriptor.class.isAssignableFrom(descriptorField.getType()),
                    () -> checkClass.getName() + " DESCRIPTOR must be of type CheckDescriptor"
            );

            descriptorField.setAccessible(true);
            CheckDescriptor descriptor =
                    (CheckDescriptor) descriptorField.get(null);

            String code = descriptor.code();

            assertTrue(
                    seenCodes.add(code),
                    () -> "Duplicate check code detected: " + code +
                          " (class " + checkClass.getSimpleName() + ")"
            );
        }
    }
}
