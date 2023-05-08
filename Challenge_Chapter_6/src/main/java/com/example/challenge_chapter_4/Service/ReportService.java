package com.example.challenge_chapter_4.Service;

import com.example.challenge_chapter_4.Model.FilmEntity;
import com.example.challenge_chapter_4.Model.JadwalEntity;
import com.example.challenge_chapter_4.Model.ReportEntity;
import com.example.challenge_chapter_4.Repository.FilmInterface;
import com.example.challenge_chapter_4.Repository.JadwalInterface;
import com.example.challenge_chapter_4.Repository.ReportInterface;
import net.sf.jasperreports.engine.*;
import net.sf.jasperreports.engine.data.JRBeanCollectionDataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.ResourceUtils;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.*;

@Service
public class ReportService {

    @Autowired
    private ReportInterface repotInterface;

    public String printReport(String format) throws FileNotFoundException, JRException {
        List<ReportEntity> reportEntities = repotInterface.findAll();
        String path = "C:\\JasperReportCh5";
        File file = ResourceUtils.getFile("classpath:data_admin.jrxml");
        JasperReport jasperReport= JasperCompileManager.compileReport(file.getAbsolutePath());
        JRBeanCollectionDataSource dataSource = new JRBeanCollectionDataSource(reportEntities);
        Map<String,Object> parameters = new HashMap<>();
        parameters.put("createBy", "Kelompok 1 Challenge 5");
        JasperPrint jasperPrint = JasperFillManager.fillReport(jasperReport, parameters, dataSource);
        if (format.equalsIgnoreCase("pdf")) {
            JasperExportManager.exportReportToPdfFile(jasperPrint, path+"\\data_admin.pdf");
        }
        return "Report generated in " + path;
    }

    //dibawah ini masih binggung

    public String printReportbyId(String format, Integer id_report) throws FileNotFoundException, JRException {
        List<ReportEntity> reportEntities = repotInterface.findByIdJadwal(id_report);
        String path = "C:\\JasperReportCh5";
        File file = ResourceUtils.getFile("classpath:Tiket.jrxml");
        JasperReport jasperReport= JasperCompileManager.compileReport(file.getAbsolutePath());
        JRBeanCollectionDataSource dataSource = new JRBeanCollectionDataSource(reportEntities);
        Map<String,Object> parameters = new HashMap<>();
        parameters.put("createBy", "Kelompok 1 Challenge 5");
        JasperPrint jasperPrint = JasperFillManager.fillReport(jasperReport, parameters, dataSource);
        if (format.equalsIgnoreCase("pdf")) {
            JasperExportManager.exportReportToPdfFile(jasperPrint, path+"\\Tiket_Nonton.pdf");
        }
        return "Report generated in " + path;
    }
}