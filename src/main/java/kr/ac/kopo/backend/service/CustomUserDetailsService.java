package kr.ac.kopo.backend.service;


import kr.ac.kopo.backend.dto.CustomUserDetails;
import kr.ac.kopo.backend.entity.UserEntity;
import kr.ac.kopo.backend.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private  final UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserEntity userData = userRepository.findByUsername(username); //조회를 할거고 조회한 데이터를 밑에서 검증할거임

        if(userData !=null){

            return new CustomUserDetails(userData);
        }

        return null;
    }
}
