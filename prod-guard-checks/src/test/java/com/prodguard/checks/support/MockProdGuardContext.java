package com.prodguard.checks.support;

import com.prodguard.core.ProdGuardContext;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class MockProdGuardContext implements ProdGuardContext {

    private final Map<String, String> properties = new HashMap<>();
    private final Map<String, Object> beansByClassName = new HashMap<>();
    private String[] profiles = new String[0];
    private Integer localServerPort;

    public MockProdGuardContext withProperty(String key, String value) {
        properties.put(key, value);
        return this;
    }

    public MockProdGuardContext withBean(String className, Object instance) {
        beansByClassName.put(className, instance);
        return this;
    }

    public MockProdGuardContext withProfiles(String... profiles) {
        this.profiles = profiles;
        return this;
    }

    @Override
    public Optional<String> getProperty(String key) {
        return Optional.ofNullable(properties.get(key));
    }

    @Override
    public <T> Optional<T> getBean(Class<T> type) {
        Object bean = beansByClassName.get(type.getName());
        if (bean == null) {
            return Optional.empty();
        }
        return Optional.of(type.cast(bean));
    }

    @Override
    public boolean hasBean(String className) {
        return beansByClassName.containsKey(className);
    }

    @Override
    public String[] getActiveProfiles() {
        return profiles;
    }

    public MockProdGuardContext withLocalServerPort(int port) {
        this.localServerPort = port;
        return this;
    }
    
    @Override
    public Optional<Integer> getLocalServerPort() {
        return Optional.ofNullable(localServerPort);
    }    
}
