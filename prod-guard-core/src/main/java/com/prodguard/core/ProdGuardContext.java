
package com.prodguard.core;

import java.util.Map;
import java.util.Optional;

/**
 * Lightweight, framework-agnostic execution context for checks.
 * Implementations adapt framework-specific contexts (e.g. Spring ApplicationContext).
 */
public interface ProdGuardContext {

    /**
     * Return a property value if present.
     */
    Optional<String> getProperty(String key);

    /**
     * Return a bean/instance of the provided type if available.
     */
    <T> Optional<T> getBean(Class<T> type);

    /**
     * Returns an array of active profiles (may be empty).
     */
    String[] getActiveProfiles();
    
    
    boolean hasBean(String className);
    
    Optional<Integer> getLocalServerPort();
}
