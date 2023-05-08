package com.example.challenge_chapter_4.Swagger;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.License;
import net.sf.jasperreports.engine.JasperFillManager;
import net.sf.jasperreports.engine.JasperPrint;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Contact;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.util.Collections;

@Configuration
@EnableSwagger2
public class SwaggerConfig {
    //memo : Any untuk scan semua dari package yang bisa di buat dokumentasinya, dan langsung generate
    @Bean
    public OpenAPI api(@Value("Challange Chapter 5 Dokumentasi Tiket Bioskop API")String appDescription,@Value("v1.0.0") String appVersion){
        //pada bagian .apis bisa juga menentukan lokasi sepesifik
        // (RequestHandlerSelectors.basePackage("com.example.challange_chapter4.Controller"))
        return new OpenAPI().info(new io.swagger.v3.oas.models.info.Info()
                .title("Dokumentasi Reservasi Tiket Bioskop Online")
                .version(appVersion).description(appDescription).termsOfService("http://swagger.io/terms/")
                .license(new License().name("Apache 2.0").url("http://springdoc.org")));
//        return new Docket(DocumentationType.SWAGGER_2).select().apis(RequestHandlerSelectors.any())
//                .paths(PathSelectors.any()).build().apiInfo(apinfo());
//        JasperPrint jasperPrint = JasperFillManager.fillReport("asd");
    }

    //untuk judul dokumentasi
//    private ApiInfo apinfo(){
//        ApiInfo apiInfo = new ApiInfo(
//                "Dokumentasi Reservasi Tiket Bioskop Online",
//                "Challange Chapter 5 Dokumentasi",
//                "API TOS",
//                "Terms of Service",
//                new Contact("Diva Juan Nur Taqarrub","","divajuan12345@gmail.com"),
//                "Apache License",
//                "www.apache.com",
//                Collections.emptyList()
//        );
//        return apiInfo;
//    }
}
