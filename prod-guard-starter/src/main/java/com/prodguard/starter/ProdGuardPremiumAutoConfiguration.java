package com.prodguard.starter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

import com.prodguard.checks.premium.security.EffectiveCookieFlagsCheck;
import com.prodguard.checks.premium.security.EffectiveCrossOriginOpenerPolicyCheck;
import com.prodguard.checks.premium.security.EffectiveCspCheck;
import com.prodguard.checks.premium.security.EffectiveHstsCheck;
import com.prodguard.checks.premium.security.EffectiveHttpsCheck;
import com.prodguard.checks.premium.security.EffectivePermissionsPolicyCheck;
import com.prodguard.checks.premium.security.EffectiveReferrerPolicyCheck;
import com.prodguard.checks.premium.security.EffectiveSecurityHeadersCheck;
import com.prodguard.checks.premium.security.EffectiveXFrameOptionsCheck;
import com.prodguard.core.ProdCheck;

import jakarta.annotation.PostConstruct;

@AutoConfiguration
@Import(ProdGuardFreeAutoConfiguration.class)
@ConditionalOnProperty(
    prefix = "prodguard.premium",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = false
)
public class ProdGuardPremiumAutoConfiguration {

	private static final Logger log = LoggerFactory.getLogger(ProdGuardPremiumAutoConfiguration.class);
	
    @Bean ProdCheck effectiveHttpsCheck() { return new EffectiveHttpsCheck(); }
    @Bean ProdCheck effectiveHstsCheck() { return new EffectiveHstsCheck(); }
    @Bean ProdCheck effectiveCspCheck() { return new EffectiveCspCheck(); }
    @Bean ProdCheck effectiveSecurityHeadersCheck() { return new EffectiveSecurityHeadersCheck(); }
    @Bean ProdCheck effectiveCookieFlagsCheck() { return new EffectiveCookieFlagsCheck(); }
    @Bean ProdCheck effectiveXFrameOptionsCheck() { return new EffectiveXFrameOptionsCheck(); }
    @Bean ProdCheck effectiveReferrerPolicyCheck() { return new EffectiveReferrerPolicyCheck(); }
    @Bean ProdCheck effectivePermissionsPolicyCheck() { return new EffectivePermissionsPolicyCheck(); }
    @Bean ProdCheck effectiveCrossOriginOpenerPolicyCheck() {
        return new EffectiveCrossOriginOpenerPolicyCheck();
    }
    
    @PostConstruct
    void premiumEnabled() {
        log.info("[prod-guard] Premium security checks enabled");
    }
}
