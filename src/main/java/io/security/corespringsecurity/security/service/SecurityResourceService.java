package io.security.corespringsecurity.security.service;

import io.security.corespringsecurity.domain.entity.Resources;
import io.security.corespringsecurity.repository.ResourcesRepository;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;


public class SecurityResourceService {

    private ResourcesRepository resourcesRepository;

    public SecurityResourceService(ResourcesRepository resourcesRepository) {
        this.resourcesRepository = resourcesRepository;
    }

    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getResourceList() {
        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> result = new LinkedHashMap<>();
        List<Resources> resourcesList = resourcesRepository.findAllResources();

        resourcesList.forEach(re -> {
            List<ConfigAttribute> configAttributeList = new ArrayList<>();
            re.getRoleSet().forEach(ro ->{
                configAttributeList.add(new SecurityConfig(ro.getRoleName()));
                result.put(new AntPathRequestMatcher(re.getResourceName()), configAttributeList);
            });
        });
        return result;
    }


}
