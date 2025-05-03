package com.techie.notes.controller;


import com.techie.notes.models.AuditLog;
import com.techie.notes.service.AuditService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/audit")
public class AuditController {

    @Autowired
    AuditService auditService;

    @GetMapping
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<List<AuditLog>> getAllAuditLogs() {
        List<AuditLog> auditLogs =auditService.getAllAuditLogs();
        return new ResponseEntity<>(auditLogs, HttpStatus.OK);
    }

    @GetMapping("/note/{id}")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<List<AuditLog>> getAuditLogById(@PathVariable Long noteId) {
        List<AuditLog> auditLogs = auditService.getAuditLogById(noteId);
        return new ResponseEntity<>(auditLogs, HttpStatus.OK);
    }
}
