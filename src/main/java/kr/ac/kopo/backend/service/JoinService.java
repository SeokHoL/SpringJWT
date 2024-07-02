package kr.ac.kopo.backend.service;


import kr.ac.kopo.backend.dto.JoinDTO;
import kr.ac.kopo.backend.entity.UserEntity;
import kr.ac.kopo.backend.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JoinService {

    private final UserRepository userRepository;

    private final BCryptPasswordEncoder bCryptPasswordEncoder; //암호 해시값

//    public JoinService(UserRepository userRepository){
//        this.userRepository = userRepository;
//    }

    public void joinProcess(JoinDTO joinDTO){

        String username = joinDTO.getUsername();
        String password =joinDTO.getPassword();

        Boolean isExist = userRepository.existsByUsername(username);

        if(isExist){

            return; //username이 존재하면 강제종료
        }

        //isExist false면
        UserEntity data = new UserEntity();

        data.setUsername(username);
        data.setPassword(bCryptPasswordEncoder.encode(password)); //암호를 해시값으로 저장해야됨.
        data.setRole("ROLE_ADMIN");

        userRepository.save(data);

    }
}
