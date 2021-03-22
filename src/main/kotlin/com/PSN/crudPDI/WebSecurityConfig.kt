package com.PSN.crudPDI

import com.PSN.crudPDI.repository.PSRepository
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.stereotype.Component


@Component
class WebSecurityConfig: WebSecurityConfigurerAdapter() {

    private lateinit var passwordEncoder: PasswordEncoder

    @Autowired
    private lateinit var repository: PSRepository

    fun WebSecurityConfig(passwordEncoder: PasswordEncoder?) {
        this.passwordEncoder = passwordEncoder!!
    }

    @Throws(Exception::class)
    override fun configure(http: HttpSecurity) {
        http
                .cors()
                .and()
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests { configurer ->
                    configurer
                            .antMatchers(
                                    "/CrudPDI/login",
                                    "/v2/api-docs",
                                    "/configuration/ui",
                                    "/swagger-resources/**",
                                    "/configuration/security",
                                    "/swagger-ui.html",
                                    "/webjars/**"
                            )
                            .permitAll()
                            .anyRequest()
                            .authenticated()

                }
                .exceptionHandling().disable()
                .oauth2ResourceServer { obj: OAuth2ResourceServerConfigurer<HttpSecurity?> -> obj.jwt() }
    }
}