package com.prodguard.starter;

import java.util.List;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.ApplicationContext;

import com.prodguard.core.ProdCheck;

@AutoConfiguration
@EnableConfigurationProperties(ProdGuardProperties.class)
public class ProdGuardBaseAutoConfiguration {

    @Bean
    public SeverityResolver severityResolver(ProdGuardProperties properties) {
        return new SeverityResolver(properties);
    }

    @Bean
    public ProdGuardRunner prodGuardRunner(
            List<ProdCheck> checks,
            ApplicationContext applicationContext,
            SeverityResolver severityResolver,
            ProdGuardProperties properties) {

        return new ProdGuardRunner(
            checks,
            applicationContext,
            severityResolver,
            properties
        );
    }
}
