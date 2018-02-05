package com.brandworkz.cas.client;

import java.util.Arrays;

import org.jasig.cas.client.session.SingleSignOutFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutFilter;

@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private AuthenticationProvider authenticationProvider;
	private AuthenticationEntryPoint authenticationEntryPoint;
	private SingleSignOutFilter singleSignOutFilter;
	private LogoutFilter logoutFilter;

	@Autowired
	public SecurityConfig(CasAuthenticationProvider authenticationProvider, AuthenticationEntryPoint authenticationEntryPoint, LogoutFilter logoutFilter, SingleSignOutFilter singleSignOutFilter) {
		this.authenticationProvider = authenticationProvider;
		this.authenticationEntryPoint = authenticationEntryPoint;
		this.logoutFilter = logoutFilter;
		this.singleSignOutFilter = singleSignOutFilter;
	}

	@Override
	protected void configure(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.authorizeRequests().regexMatchers("/secured.*", "/login").authenticated().and().authorizeRequests()
				.regexMatchers("/").permitAll().and().httpBasic().authenticationEntryPoint(authenticationEntryPoint)
				.and().logout().logoutSuccessUrl("/logout").and()
				.addFilterBefore(singleSignOutFilter, CasAuthenticationFilter.class)
				.addFilterBefore(logoutFilter, LogoutFilter.class);
	}

	@Override
	protected void configure(AuthenticationManagerBuilder builder) throws Exception {
		builder.authenticationProvider(authenticationProvider);
	}

	@Override
	protected AuthenticationManager authenticationManager() throws Exception {
		return new ProviderManager(Arrays.asList(authenticationProvider));
	}

	@Bean
	public CasAuthenticationFilter casAuthenticationFilter(ServiceProperties serviceProperties) throws Exception {
		CasAuthenticationFilter filter = new CasAuthenticationFilter();
		filter.setServiceProperties(serviceProperties);
		filter.setAuthenticationManager(authenticationManager());
		return filter;
	}
}
