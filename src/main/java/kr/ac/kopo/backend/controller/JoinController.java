package kr.ac.kopo.backend.controller;

import kr.ac.kopo.backend.dto.JoinDTO;
import kr.ac.kopo.backend.service.JoinService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService; //

//    public JoinController(JoinService joinService){  @RequiredArgsConstructor를 선언하면 기본생성자를 만들어줌. 생성자주입
//        this.joinService = joinService;
//    }

    @PostMapping("/join")
    public String joinProcess(JoinDTO joinDTO){
        joinService.joinProcess(joinDTO);

        return "ok";
    }
}
