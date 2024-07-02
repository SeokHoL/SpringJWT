package kr.ac.kopo.backend.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kr.ac.kopo.backend.dto.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Collection;
import java.util.Iterator;

@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException {

        //클라이언트요청에 username, password 추출
        String username = obtainUsername(httpServletRequest);
        String password = obtainPassword(httpServletRequest);

        System.out.println(username);


        //스프링 시큐리티에서 username과 passowrd를 검증하기 위해서는 token에 담아야함
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username,password,null); //UsernamePasswordAuthenticationToken 토큰바구니에 담아서 보낸다.

        //token에 담은 검증을 위한  authenticationManager
        return authenticationManager.authenticate(authenticationToken);
    }

    //로그인 성공시 실행하는 메서드(여기서 JWT를 발급하면 됨)
    @Override
    protected void successfulAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain, Authentication authentication){

        CustomUserDetails customUserDetails =(CustomUserDetails) authentication.getPrincipal();

        String username = customUserDetails.getUsername();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();

        String role = auth.getAuthority();

        String token = jwtUtil.createJwt(username,role,60*60*10L);

        httpServletResponse.addHeader("Authorization","Bearer" +token); //Authorization (키값)  "Bearer" +token (벨류값)
    }

    //로그인 실패시 실행하는 메서드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException failed){

        httpServletResponse.setStatus(401);
    }
}
