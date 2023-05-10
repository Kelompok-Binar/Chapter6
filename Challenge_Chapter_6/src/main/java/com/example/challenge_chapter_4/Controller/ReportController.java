package com.example.challenge_chapter_4.Controller;

import com.example.challenge_chapter_4.Model.ReportEntity;
import com.example.challenge_chapter_4.Service.ReportService;
import io.swagger.annotations.Api;
import net.sf.jasperreports.engine.JRException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.FileNotFoundException;

@RestController
@RequestMapping(value ="/Report")
@Api(value = "Report")
public class ReportController {

    @Autowired
    ReportService reportService;

    @GetMapping("/report/{format}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String generateReport(@PathVariable String format) throws JRException, FileNotFoundException {
        return reportService.printReport(format);
    }

    @GetMapping("/report/{format}/{id_report}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String generateReportbyID(@PathVariable String format, @PathVariable Integer id_report) throws JRException, FileNotFoundException {
        return reportService.printReportbyId(format, id_report);
    }
}