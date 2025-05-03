package com.techie.notes.service.impl;

import com.techie.notes.models.AuditLog;
import com.techie.notes.models.Note;
import com.techie.notes.repository.AuditRepository;
import com.techie.notes.service.AuditService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuditServiceImpl implements AuditService {


    private final AuditRepository auditRepository;

    @Override
    public void logNoteCreation(String username, Note note) {
        AuditLog auditLog = new AuditLog();
        auditLog.setAction("CREATE");
        auditLog.setUsername(username);
        auditLog.setNoteId(note.getId());
        auditLog.setNoteContent(note.getContent());
        auditLog.setTimestamp(LocalDateTime.now());
        auditRepository.save(auditLog);
    }

    @Override
    public void logNoteUpdate(String username, Note note) {
        AuditLog auditLog = new AuditLog();
        auditLog.setAction("UPDATE");
        auditLog.setUsername(username);
        auditLog.setNoteId(note.getId());
        auditLog.setNoteContent(note.getContent());
        auditLog.setTimestamp(LocalDateTime.now());
        auditRepository.save(auditLog);
    }

    @Override
    public void logNoteDeletion(String username, Long noteId) {
        AuditLog auditLog = new AuditLog();
        auditLog.setAction("DELETE");
        auditLog.setUsername(username);
        auditLog.setNoteId(noteId);
        auditLog.setTimestamp(LocalDateTime.now());
        auditRepository.save(auditLog);
    }

    @Override
    public List<AuditLog> getAllAuditLogs() {
        return auditRepository.findAll();
    }

    public List<AuditLog> getAuditLogById(Long noteId) {
        return auditRepository.findByNoteId(noteId);
    }
}
