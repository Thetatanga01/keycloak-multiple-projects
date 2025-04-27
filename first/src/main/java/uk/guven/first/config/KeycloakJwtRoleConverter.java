package uk.guven.first.config;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class KeycloakJwtRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private static final String REALM_ACCESS = "realm_access";
    private static final String ROLES = "roles";
    private static final String RESOURCE_ACCESS = "resource_access";
    private static final String GROUPS = "groups";
    public static final String APPENDIX = "STOCK_";
    public static final String GROUP_PREFIX = "GROUP_";

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();

        // Realm roles
        Map<String, Object> realmAccess = jwt.getClaimAsMap(REALM_ACCESS);
        if (realmAccess != null && realmAccess.containsKey(ROLES)) {
            List<String> roles = (List<String>) realmAccess.get(ROLES);
            if (roles != null) {
                Collection<GrantedAuthority> realmRoles = roles.stream()
                    .map(role -> new SimpleGrantedAuthority(APPENDIX + role))
                    .collect(Collectors.toList());
                grantedAuthorities.addAll(realmRoles);

                // Debug için rolleri yazdıralım
                System.out.println("Realm Roles: " + roles);
            }
        }

        // Resource roles (client specific roles)
        Map<String, Object> resourceAccess = jwt.getClaimAsMap(RESOURCE_ACCESS);
        if (resourceAccess != null) {
            resourceAccess.forEach((clientId, clientAccess) -> {
                if (clientAccess instanceof Map) {
                    Map<String, Object> clientAccessMap = (Map<String, Object>) clientAccess;
                    if (clientAccessMap.containsKey(ROLES)) {
                        List<String> clientRoles = (List<String>) clientAccessMap.get(ROLES);
                        if (clientRoles != null) {
                            Collection<GrantedAuthority> resourceRoles = clientRoles.stream()
                                .map(role -> new SimpleGrantedAuthority(APPENDIX + clientId + "_" + role))
                                .collect(Collectors.toList());
                            grantedAuthorities.addAll(resourceRoles);

                            // Debug için rolleri yazdıralım
                            System.out.println("Client '" + clientId + "' Roles: " + clientRoles);
                        }
                    }
                }
            });
        }

        // AD Gruplarını ekleyelim
        List<String> groups = jwt.getClaimAsStringList(GROUPS);
        if (groups != null && !groups.isEmpty()) {
            Collection<GrantedAuthority> groupAuthorities = groups.stream()
                .map(group -> new SimpleGrantedAuthority(GROUP_PREFIX + group))
                .collect(Collectors.toList());
            grantedAuthorities.addAll(groupAuthorities);

            // Debug için grupları yazdıralım
            System.out.println("User Groups: " + groups);
        }

        System.out.println("Granted Authorities: " + grantedAuthorities);
        return grantedAuthorities;
    }
}
