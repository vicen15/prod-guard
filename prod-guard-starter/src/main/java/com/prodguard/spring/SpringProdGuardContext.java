package com.prodguard.spring;

import java.util.Optional;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.core.env.Environment;

import com.prodguard.core.ProdGuardContext;

public class SpringProdGuardContext implements ProdGuardContext {

    private final ApplicationContext applicationContext;
    private final Environment environment;

    public SpringProdGuardContext(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
        this.environment = applicationContext.getEnvironment();
    }

    @Override
    public Optional<String> getProperty(String key) {
        return Optional.ofNullable(environment.getProperty(key));
    }

    @Override
    public boolean hasBean(String className) {
        try {
            Class<?> clazz = Class.forName(className);
            return !applicationContext.getBeansOfType(clazz).isEmpty();
        } catch (ClassNotFoundException ex) {
            return false;
        }
    }

    @Override
    public <T> Optional<T> getBean(Class<T> type) {
        try {
            return Optional.of(applicationContext.getBean(type));
        } catch (BeansException ex) {
            return Optional.empty();
        }
    }

    @Override
    public String[] getActiveProfiles() {
        return environment.getActiveProfiles();
    }

    @Override
    public Optional<Integer> getLocalServerPort() {
        return Optional.ofNullable(
            environment.getProperty("local.server.port", Integer.class)
        );
    }
}
