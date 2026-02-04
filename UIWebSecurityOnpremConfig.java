package de.swisslife.koala.userclient.security;

import de.swisslife.koala.userclient.common.KoalaSettings;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.CacheControlConfig;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.CacheControlHeadersWriter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.apache.commons.lang3.StringUtils.isBlank;

@Configuration
@Profile("form-login")
public class UIWebSecurityOnpremConfig implements KoalaRechte, KoalaSecurityConstants {

  private static final Logger LOG = LogManager.getLogger();
  private static final String LOGIN_PAGE_URL = "/login.jsp";
  @Autowired
  private KoalaUserDetailsAuthenticationProvider koalaUserDetailsAuthenticationProvider;
  @Autowired
  private KoalaLogoutSuccessHandler koalaLogoutSuccessHandler;
  @Autowired
  private KoalaSettings koalaSettings;


  // Public
  final RequestMatcher publicAPI = new OrRequestMatcher(//
      PathPatternRequestMatcher.withDefaults().matcher("/"), //
      PathPatternRequestMatcher.withDefaults().matcher("/index.html"), //
      PathPatternRequestMatcher.withDefaults().matcher("/resources/**"), //
      PathPatternRequestMatcher.withDefaults().matcher("/js/**"), //
      PathPatternRequestMatcher.withDefaults().matcher("/css/**"), //
      PathPatternRequestMatcher.withDefaults().matcher("/img/**"), //
      PathPatternRequestMatcher.withDefaults().matcher("/webjars/**"), //
      PathPatternRequestMatcher.withDefaults().matcher("/**favicon.ico"),
      PathPatternRequestMatcher.withDefaults().matcher("/javax.faces.resource/**"), //
      PathPatternRequestMatcher.withDefaults().matcher(LOGIN_PAGE_URL));


  @Bean
  public WebSecurityCustomizer webSecurityCustomizer() {
    return (web) -> web.ignoring().requestMatchers(publicAPI);
  }

  @Bean("uiFilterChain")
  @Order(2)
  public SecurityFilterChain uiSecurityConfig(HttpSecurity http) throws Exception {
    http.csrf(AbstractHttpConfigurer::disable);

    http.headers(headers -> {
      headers.cacheControl(CacheControlConfig::disable);
      headers
          .httpStrictTransportSecurity(cf -> cf.includeSubDomains(true).maxAgeInSeconds(Duration.ofDays(365).getSeconds()))
          .referrerPolicy(rp -> rp.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
          .frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin);
    });


    // org.springframework.security.web.authentication.session.ConcurrentSessionControlAuthenticationStrategy
    // The default value is 1. Use -1 for unlimited sessions.
    http.sessionManagement(sm -> sm.maximumSessions(-1).sessionRegistry(sessionRegistry()));

    // Feature toggle
    List<PathPatternRequestMatcher> featuresDisabled = new ArrayList<>();
    featuresDisabled.add(PathPatternRequestMatcher.withDefaults().matcher("/notexist")); //RequestMatcher must contain a value
    // TODO add auftrag
    final RequestMatcher featureDisabled = new OrRequestMatcher(
        featuresDisabled.toArray(new PathPatternRequestMatcher[0]));

    // UI
    final RequestMatcher uiRequests = new NegatedRequestMatcher(PathPatternRequestMatcher.withDefaults().matcher("/actuator/**"));

    // @formatter:off
    http.securityMatcher(uiRequests).authorizeHttpRequests(auth -> auth //
          .requestMatchers(publicAPI).permitAll() //
            .requestMatchers(PathPatternRequestMatcher.withDefaults().matcher("/archiv")).authenticated() //
            .requestMatchers(PathPatternRequestMatcher.withDefaults().matcher("/monitoring/**")).hasAuthority(KOALA_ADMIN) //
            .requestMatchers(PathPatternRequestMatcher.withDefaults().matcher("/admin/**")).hasAuthority(KOALA_ADMIN) //
            .requestMatchers(PathPatternRequestMatcher.withDefaults().matcher("/uebergreifend/**")).hasAnyAuthority(KOALA_UEBERGREIFEND, KOALA_ADMIN) //
            .requestMatchers(PathPatternRequestMatcher.withDefaults().matcher("/antragev/dashboard.xhtml")).hasAuthority(KOALA_ADMIN) //
            .requestMatchers(PathPatternRequestMatcher.withDefaults().matcher("/antragev/**")).hasAnyAuthority(KOALA_ANTRAGEV, KOALA_ADMIN) //
            .requestMatchers(PathPatternRequestMatcher.withDefaults().matcher("/voranfrage/**")).hasAnyAuthority(KOALA_VORANFRAGE, KOALA_ADMIN) //
            .requestMatchers(PathPatternRequestMatcher.withDefaults().matcher("/stornogefahrmitteilung/**")).hasAnyAuthority(KOALA_ADMIN, KOALA_STORNOGEFAHR) //
            .requestMatchers(PathPatternRequestMatcher.withDefaults().matcher("/sgm-starten.xhtml")).hasAnyAuthority(KOALA_ADMIN, KOALA_STORNOGEFAHR) //
            .requestMatchers(PathPatternRequestMatcher.withDefaults().matcher("/leistung/**")).hasAnyAuthority(KOALA_ADMIN, KOALA_BIOMETRIE) //
            .requestMatchers(PathPatternRequestMatcher.withDefaults().matcher("/sachbearbeitung/**")).hasAnyAuthority(KOALA_ADMIN, KOALA_SACHBEARBEITUNG) //
            .requestMatchers(PathPatternRequestMatcher.withDefaults().matcher("/loeschung/**")).hasAnyAuthority(KOALA_ADMIN, KOALA_COC) //
            .requestMatchers(PathPatternRequestMatcher.withDefaults().matcher("/dokumentverteilung/**"))
          .hasAnyAuthority(KOALA_DOKUMENTVERTEILUNG, KOALA_ADMIN) //
          .requestMatchers(featureDisabled).denyAll()
          .requestMatchers(PathPatternRequestMatcher.withDefaults().matcher("/**.xhtml")).hasAuthority(KOALA_LOGIN) // leistung, sachbearbeitung, uebergreifend
          .anyRequest().denyAll())
        .authenticationProvider(koalaUserDetailsAuthenticationProvider)
        .formLogin(config-> config.loginPage(LOGIN_PAGE_URL).permitAll()
          .loginProcessingUrl("/j_spring_security_check").usernameParameter("j_username")
          .passwordParameter("j_password").defaultSuccessUrl("/index.xhtml")
          .failureHandler(new KoalaFormLoginFailureHandler()))
        .exceptionHandling(config-> config.accessDeniedHandler(new KoalaAccessDeniedHandler()))
        .logout(config-> config.addLogoutHandler(new KeycloakLogoutHandler())
            .logoutRequestMatcher(PathPatternRequestMatcher.withDefaults().matcher("/logout"))
            .invalidateHttpSession(true)
            .logoutSuccessHandler(koalaLogoutSuccessHandler)
            .permitAll())
        .addFilterBefore(new AjaxAwareSecurityFilter(), UsernamePasswordAuthenticationFilter.class)
        .addFilterBefore(new KoalaSSOFilter(), AjaxAwareSecurityFilter.class)
        .addFilterBefore(new KoalaCacheControlFilter(), AjaxAwareSecurityFilter.class);
    // @formatter:on
    return http.build();
  }

  @Bean
  public SessionRegistry sessionRegistry() {
    return new SessionRegistryImpl();
  }

  @Bean
  public HttpSessionEventPublisher httpSessionEventPublisher() {
    return new HttpSessionEventPublisher();
  }

  /**
   * Der {@link CacheControlConfig} von Spring Security kann nicht URL-selektiv angewandt werden.<br>
   * <p>
   * Folgende Steps sollen in {@link HttpSecurity} gemacht werden, um selektiv Cache-Control zu ermöglichen.
   *
   * <li>http.headers().cacheControl().disable() &nbsp;&nbsp;&nbsp; //disable CacheControl global</li>
   * <li>http.addFilterBefore(new KoalaCacheControlFilter(), AjaxAwareSecurityFilter.class); &nbsp;&nbsp;//register
   * Filter</li>
   *
   * <br>
   * In dem KoalaCacheControlFilter wird {@link CacheControlHeadersWriter} nur angewandt wenn der Request nicht dem
   * Proxy-Servlet-Pfad entspricht.
   */
  class KoalaCacheControlFilter implements Filter {
    public static final String ARCHIV_PROXY_SERVLET_PATH = "/archiv";
    private CacheControlHeadersWriter writer;

    public KoalaCacheControlFilter() {
      writer = new CacheControlHeadersWriter();
    }

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
      // make sonar happy
    }

    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response,
                         final FilterChain chain) throws IOException, ServletException {
      HttpServletRequest req = (HttpServletRequest) request;
      HttpServletResponse res = (HttpServletResponse) response;
      if (!ARCHIV_PROXY_SERVLET_PATH.equals(req.getServletPath())) {
        writer.writeHeaders(req, res);
      }
      chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
      // make sonar happy
    }
  }

  /**
   * Existiert din Attribut "remote-user" in http-header, wird der Benutzer dann als vorauthentifiziert festgestellt.
   */
  class KoalaSSOFilter implements Filter, KoalaSecurityConstants {

    private KoalaFormLoginFailureHandler loginFailureHandler;

    public KoalaSSOFilter() {
      super();
      this.loginFailureHandler = new KoalaFormLoginFailureHandler();
    }

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
      // make sonar happy
    }

    @Override
    public void doFilter(final ServletRequest servletRequest, final ServletResponse servletResponse,
                         final FilterChain chain) throws IOException, ServletException {
      HttpServletRequest request = (HttpServletRequest) servletRequest;
      HttpServletResponse response = (HttpServletResponse) servletResponse;

      if (!bypassSSOFilter(request)) {
        String username = getSSOToken(request);
        try {
          Benutzer principle = koalaUserDetailsAuthenticationProvider.erstelleBenutzer(username, username);
          Authentication auth = new UsernamePasswordAuthenticationToken(principle, username,
              principle.getAuthorities());
          SecurityContextHolder.getContext().setAuthentication(auth);
        } catch (AuthenticationException te) {
          loginFailureHandler.onAuthenticationFailure(request, response, te);
          return;
        } catch (Exception ex) {
          HttpSession session = request.getSession();
          session.setAttribute(SESSION_LOGIN_PARAM, KEY_TECHNICAL_ERROR);
          LOG.error("Unerwarteter Fehler ist aufgetreten:", ex);
          response.sendRedirect(request.getContextPath() + LOGIN_PAGE_URL);
          return;
        }
      }

      chain.doFilter(servletRequest, response);

    }

    private boolean bypassSSOFilter(final HttpServletRequest request) {
      boolean loginPage = request.getRequestURI().contains("j_spring_security_check")
          || request.getRequestURI().contains(LOGIN_PAGE_URL);
      if (loginPage) {
        return true;
      }

      String username = getSSOToken(request);
      if (isBlank(username)) {
        return true;
      }

      Authentication authToken = SecurityContextHolder.getContext().getAuthentication();
      if (authToken != null && authToken.isAuthenticated()) {
        return true;
      }
      return false;
    }

    private String getSSOToken(final HttpServletRequest request) {
      return request.getHeader(SSO_PRINCIPLE_TOKEN);
    }
  }
}
