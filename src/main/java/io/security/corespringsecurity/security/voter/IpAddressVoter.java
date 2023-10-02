package io.security.corespringsecurity.security.voter;

import io.security.corespringsecurity.security.service.SecurityResourceService;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import java.util.Collection;
import java.util.List;


public class IpAddressVoter implements AccessDecisionVoter {

    private SecurityResourceService securityResourceService;

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return false;
    }

    @Override
    public int vote(Authentication authentication, Object object, Collection collection) {
        WebAuthenticationDetails details = (WebAuthenticationDetails) authentication.getDetails();
        String remoteAddress = details.getRemoteAddress();
        List<String> accessIpList = securityResourceService.getAccessIpList();
        int result = ACCESS_DENIED;

        for (String ipAddress : accessIpList) {
            if (remoteAddress.equals(ipAddress)) {
                return ACCESS_ABSTAIN;
            }
        }
        if (result == ACCESS_DENIED) {
            throw new AccessDeniedException("Invalid Ip Address");
        }
        return result;
    }

    @Override
    public boolean supports(Class clazz) {
        return false;
    }
}
