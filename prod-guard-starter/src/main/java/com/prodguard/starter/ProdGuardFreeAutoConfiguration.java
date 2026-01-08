package com.prodguard.starter;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;

import com.prodguard.checks.free.ActuatorExposureCheck;
import com.prodguard.checks.free.CsrfDisabledCheck;
import com.prodguard.checks.free.DatasourcePoolCheck;
import com.prodguard.checks.free.DebugLoggingCheck;
import com.prodguard.checks.free.HeapSizeCheck;
import com.prodguard.checks.free.HttpsEnabledCheck;
import com.prodguard.checks.free.SecurityHeadersCheck;
import com.prodguard.checks.free.ShowSqlCheck;
import com.prodguard.checks.free.StacktraceExposureCheck;
import com.prodguard.checks.free.TimeoutDefaultsCheck;
import com.prodguard.core.ProdCheck;

@AutoConfiguration
public class ProdGuardFreeAutoConfiguration {

    @Bean
    public ProdCheck debugLoggingCheck() { return new DebugLoggingCheck(); }

    @Bean
    public ProdCheck showSqlCheck() { return new ShowSqlCheck(); }

    @Bean
    public ProdCheck stacktraceExposureCheck() { return new StacktraceExposureCheck(); }

    @Bean
    public ProdCheck actuatorExposureCheck() { return new ActuatorExposureCheck(); }

    @Bean
    public ProdCheck httpsEnabledCheck() { return new HttpsEnabledCheck(); }

    @Bean
    public ProdCheck securityHeadersCheck() { return new SecurityHeadersCheck(); }

    @Bean
    public ProdCheck csrfDisabledCheck() { return new CsrfDisabledCheck(); }

    @Bean
    public ProdCheck heapSizeCheck() { return new HeapSizeCheck(); }

    @Bean
    public ProdCheck datasourcePoolCheck() { return new DatasourcePoolCheck(); }

    @Bean
    public ProdCheck timeoutDefaultsCheck() { return new TimeoutDefaultsCheck(); }
    
}