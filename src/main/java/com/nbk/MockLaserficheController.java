package com.nbk;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.ObjectMapper;

@RestController
public class MockLaserficheController {

    private static final Logger logger = LoggerFactory.getLogger(MockLaserficheController.class);

    @GetMapping(value = "/mock/LaserficheLOS/api/Values/GetDocument", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> getDocument() throws Exception {

        // load reso=ponse from the response.json file
        String responseJson = new String(Files.readAllBytes(Paths.get("src/main/resources/response.json")));
        Map<String, Object> response = new ObjectMapper().readValue(responseJson, Map.class);
        return response;
    }

}
