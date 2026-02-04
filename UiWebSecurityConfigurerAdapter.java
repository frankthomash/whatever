/**
 *
 */
package de.swisslife.versandsteuerung.security;

import de.swisslife.versandsteuerung.security.handler.VSAccessDeniedHandler;
import de.swisslife.versandsteuerung.security.handler.VSFormLoginFailureHandler;
import de.swisslife.versandsteuerung.security.handler.VSLogoutSuccessHandler;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Security Konfiguration für die Weboberfläche (JSF / SSO oder form-based
 * auth))
 * Wir brauchen @Order, damit zurerst die Web-UI Zugriffe und dann erst der Rest-Service betrachtet wird
 *
 * @author liny,karasm
 */
@Configuration
public class UiWebSecurityConfigurerAdapter {

  public static final String SESSION_PARAM_LOGOUT = "logout";
  public static final String SESSION_PARAM_ERROR = "error";

  private static RequestMatcher htmlAnywhere() {
        return new RegexRequestMatcher(".+\\.html$", null);
  }
  private static RequestMatcher xhtmlAnywhere() {
        return new RegexRequestMatcher(".+\\.xhtml$", null);
  }

  @Bean
  @Order(1)
  public SessionRegistry sessionRegistry() {
		return new SessionRegistryImpl();
	}

  @Bean(name = "uiSecurityFilterChain")
  @Order(1)
  SecurityFilterChain uiFilterChain(HttpSecurity http) throws Exception {

    http.csrf(AbstractHttpConfigurer::disable);

    // org.springframework.security.web.authentication.session.ConcurrentSessionControlAuthenticationStrategy
    // The default value is 1. Use -1 for unlimited sessions.
    http.sessionManagement(management -> management.maximumSessions(-1).sessionRegistry(sessionRegistry()));

    RequestMatcher uiRequests = new OrRequestMatcher(
            PathRequest.toStaticResources().atCommonLocations(), // da ist auch META-INF/resources/** dabei
            PathPatternRequestMatcher.withDefaults().matcher("/assets/**"),
            PathPatternRequestMatcher.withDefaults().matcher("/styles/**"),
            PathPatternRequestMatcher.withDefaults().matcher("/favicon.ico"),
            PathPatternRequestMatcher.withDefaults().matcher("/jakarta.faces.resource/**"),
            PathPatternRequestMatcher.withDefaults().matcher("/javax.faces.resource/**"),
            PathPatternRequestMatcher.withDefaults().matcher("/"),   // welcome
            PathPatternRequestMatcher.withDefaults().matcher("/index.html"),
            PathPatternRequestMatcher.withDefaults().matcher("/ui/**")
    );

    // Diese Konfiguration soll nur für UI aktiviert werden (den rest macht der andere Api-WebSecurity-Adapter)
    http.securityMatcher(uiRequests)
            .authorizeHttpRequests(req -> req
					// static
					.requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
                    .requestMatchers("/assets/**","/styles/**","/favicon.ico").permitAll()
                    .requestMatchers("/jakarta.faces.resource/**","/javax.faces.resource/**").permitAll()
					// public UI
					.requestMatchers("/","/index.html","/ui/login.xhtml","/ui/error.xhtml").permitAll()
					// protected UI
                    .requestMatchers("/ui/**").hasAuthority(Authority.WEBUSER.name())
					// anything else matched by this chain
					.anyRequest().denyAll()
			)
            .formLogin(login -> login//
                    .loginPage("/ui/login.xhtml").permitAll()
                    // Spring Security den POST auf derselben JSF URL ausführen lassen
                    .loginProcessingUrl("/ui/login.xhtml")
                    .usernameParameter("loginForm:username")
                    .passwordParameter("loginForm:password")
                    .defaultSuccessUrl("/ui/regeln/regelnKollektiv.xhtml", true)
                    .failureHandler(new VSFormLoginFailureHandler()))
            .exceptionHandling(handling -> handling
                    .accessDeniedHandler(new VSAccessDeniedHandler()))
            .logout(logout -> logout
                    .logoutUrl("/ui/logout.xhtml")
                    .invalidateHttpSession(true)
                    .logoutSuccessHandler(new VSLogoutSuccessHandler())
                    .permitAll());
    return http.build();
	}
}
