package com.prodguard.checks.free;

import com.prodguard.core.CheckDescriptor;
import com.prodguard.core.ProdCheck;
import org.junit.jupiter.api.Test;
import org.reflections.Reflections;

import java.lang.reflect.Field;
import java.util.Set;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class CheckCodeFormatTest {

    private static final Pattern CODE_PATTERN =
            Pattern.compile("PG-\\d{3}");

    @Test
    void allCheckCodesMustFollowStandardFormat() throws Exception {
        Reflections reflections = new Reflections("com.prodguard.checks.free");

        Set<Class<? extends ProdCheck>> checkClasses =
                reflections.getSubTypesOf(ProdCheck.class);

        for (Class<? extends ProdCheck> checkClass : checkClasses) {

            Field descriptorField =
                    checkClass.getDeclaredField("DESCRIPTOR");

            descriptorField.setAccessible(true);
            CheckDescriptor descriptor =
                    (CheckDescriptor) descriptorField.get(null);

            String code = descriptor.code();

            assertTrue(
                    CODE_PATTERN.matcher(code).matches(),
                    () -> "Invalid check code format: '" + code +
                          "' in " + checkClass.getSimpleName() +
                          " (expected PG-###)"
            );
        }
    }
}
