package io.security.corespringsecurity.security.configs;

import io.security.corespringsecurity.repository.ResourcesRepository;
import io.security.corespringsecurity.security.service.SecurityResourceService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {

    @Bean
    public SecurityResourceService securityResourceService(ResourcesRepository resourcesRepository) {
        SecurityResourceService securityResourceService = new SecurityResourceService(resourcesRepository);
        return securityResourceService;
    }

}
