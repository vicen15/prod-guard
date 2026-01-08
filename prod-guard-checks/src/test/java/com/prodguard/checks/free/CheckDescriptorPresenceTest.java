package com.prodguard.checks.free;

import com.prodguard.core.CheckDescriptor;
import com.prodguard.core.ProdCheck;
import org.junit.jupiter.api.Test;
import org.reflections.Reflections;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class CheckDescriptorPresenceTest {

    @Test
    void allChecksMustDeclareDescriptor() {
        Reflections reflections = new Reflections("com.prodguard.checks.free");

        Set<Class<? extends ProdCheck>> checkClasses =
                reflections.getSubTypesOf(ProdCheck.class);

        for (Class<? extends ProdCheck> checkClass : checkClasses) {

            Field descriptorField;
            try {
                descriptorField = checkClass.getDeclaredField("DESCRIPTOR");
            } catch (NoSuchFieldException e) {
                fail("Check " + checkClass.getSimpleName()
                        + " does not declare a DESCRIPTOR field");
                return;
            }

            assertTrue(
                    CheckDescriptor.class.isAssignableFrom(descriptorField.getType()),
                    () -> "DESCRIPTOR in " + checkClass.getSimpleName()
                            + " must be of type CheckDescriptor"
            );

            int modifiers = descriptorField.getModifiers();

            assertTrue(
                    Modifier.isStatic(modifiers),
                    () -> "DESCRIPTOR in " + checkClass.getSimpleName()
                            + " must be static"
            );
        }
    }
}
