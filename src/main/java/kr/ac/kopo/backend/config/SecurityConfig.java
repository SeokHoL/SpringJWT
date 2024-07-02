package kr.ac.kopo.backend.config;

import kr.ac.kopo.backend.jwt.JWTFilter;
import kr.ac.kopo.backend.jwt.JWTUtil;
import kr.ac.kopo.backend.jwt.LoginFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.OAuth2ClientDsl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration //클래스를 설정 클래스로 정의합니다
@EnableWebSecurity // 웹 보안 지원을 활성화하는 어노테이션입니다. 이 어노테이션은 Spring Security를 사용하는 데 필요한 설정을 자동으로 구성합니다.
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil;

    @Bean // AuthenticationManager을 Bean에 등록
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws  Exception{

        return configuration.getAuthenticationManager();
    }

    @Bean //어디서든 사용할수 있게 bean에 등록함
    public BCryptPasswordEncoder bCryptPasswordEncoder(){  //비밀번호를 암호화 할때 사용함.

        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception{

        //csrf disable
        httpSecurity
                .csrf((auth) -> auth.disable());  // CSRF 보호 비활성화

        //Form 로그인 방식 disable
        httpSecurity
                .formLogin((auth) -> auth.disable());

        //http basic 인증방식 disable
        httpSecurity
                .httpBasic((auth) -> auth.disable());

        //경로별 인가 작업
        httpSecurity
                .authorizeHttpRequests((auth)->auth
                        .requestMatchers("/login","/","/join").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated() // 그외의 사용자는 로그인 한 사용자만 가능.
                );
        httpSecurity
                .addFilterBefore(new JWTFilter(jwtUtil),LoginFilter.class);

        httpSecurity
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration),jwtUtil), UsernamePasswordAuthenticationFilter.class);

        //세션 설정
        httpSecurity
                .sessionManagement((session)-> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS) //JWT에서는 항상 세션을 STATELESS 로 설정해야된다.
                );

        return httpSecurity.build();


    }
}
