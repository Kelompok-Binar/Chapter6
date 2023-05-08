package com.example.challenge_chapter_4.Response;

import org.springframework.stereotype.Component;

@Component
public class CommonResponseGenerator<T>{
    public <T> CommonResponse<T> succsesResponse(T datas, String msg){
        CommonResponse commonResponse = new CommonResponse<>();
        commonResponse.setStatus("200");
        commonResponse.setMsg(msg);
        commonResponse.setDatas(datas);

        return commonResponse;
    }

    public <T> CommonResponse<T> failedResponse(String msg){
        CommonResponse commonResponse = new CommonResponse<>();
        commonResponse.setStatus("500");
        commonResponse.setMsg(msg);

        return commonResponse;
    }
}
