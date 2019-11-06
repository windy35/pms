package com.web.pms.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

import javax.annotation.Resource;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Resource
    public void configGloabl(AuthenticationManagerBuilder auth)throws Exception{
        auth.inMemoryAuthentication().withUser("wenjava").password("hello").roles("USER")
                .and().withUser("admin").password("hello").roles("USER", "ADMIN");

    }
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 表示所有的访问都必须认证，认证处理后才可以正常进行
        http.httpBasic().and().authorizeRequests().anyRequest().fullyAuthenticated();
        // 所有的rest服务一定要设置为无状态，以提升操作效率和性能
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

    }
}
