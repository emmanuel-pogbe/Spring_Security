package com.shopleft.spring_security.config;

import org.springframework.security.ldap.userdetails.LdapUserDetailsService;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;

public class TestLdap {
    public void test(BaseLdapPathContextSource contextSource) {
        FilterBasedLdapUserSearch search = new FilterBasedLdapUserSearch("ou=people", "(uid={0})", contextSource);
        DefaultLdapAuthoritiesPopulator authorities = new DefaultLdapAuthoritiesPopulator(contextSource, "ou=groups");
        authorities.setGroupSearchFilter("(uniqueMember={0})");
        authorities.setRolePrefix("ROLE_");
        LdapUserDetailsService svc = new LdapUserDetailsService(search, authorities);
    }
}
