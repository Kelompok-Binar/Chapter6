package com.example.challenge_chapter_4.Controller;

import com.example.challenge_chapter_4.Model.StudioEntity;
import com.example.challenge_chapter_4.Response.CommonResponse;
import com.example.challenge_chapter_4.Response.CommonResponseGenerator;
import com.example.challenge_chapter_4.Service.StudioService;
import io.swagger.annotations.Api;
import io.swagger.v3.oas.annotations.Operation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping(value ="/Studio")
@Api(value = "Studio")
public class StudioController {
    @Autowired
    StudioService ss;
    @Autowired
    CommonResponseGenerator srg;

    //cara mendapatkan page number dan size ?pageNumber=1&pageSize=2
    @GetMapping
    @Operation(description = "Menampilkan Semua Studio")
    public CommonResponse<ResponseEntity<List<StudioEntity>>> getAll(
            @RequestParam(defaultValue = "0")int pageNumber,
            @RequestParam(defaultValue = "10") int pageSize){

        try {
            Page<StudioEntity> result = ss.getAll(pageNumber, pageSize);
            List<StudioEntity> data = result.getContent();
//        int currentPage = result.getNumber();
//        int totalPages = result.getTotalPages();
            long totalItems = result.getTotalElements();

            HttpHeaders headers = new HttpHeaders();
            headers.add("X-Total-Count", String.valueOf(totalItems));
            log.info("Sukses Tampil Data");
            return srg.succsesResponse(ResponseEntity.ok().headers(headers).body(data),"Sukses Tampil Data");
        }
        catch (Exception e){
            log.warn(String.valueOf(e));
            return srg.failedResponse(e.getMessage());
        }

    }
//    @GetMapping(value = "Studios/{studio}/{nomor_kursi}")
//    public StudioEntity getByStudio(@PathVariable char studio, @PathVariable Integer nomor_kursi){
//        return ss.getByStudio(studio, nomor_kursi);
//    }
}
