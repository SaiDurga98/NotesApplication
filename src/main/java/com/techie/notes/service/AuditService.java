package com.techie.notes.service;

import com.techie.notes.models.AuditLog;
import com.techie.notes.models.Note;

import java.util.List;
import java.util.Optional;


public interface AuditService {

    void logNoteCreation(String username, Note note);

    void logNoteUpdate(String username, Note note);

    void logNoteDeletion(String username, Long noteId);

    List<AuditLog> getAllAuditLogs();

    List<AuditLog> getAuditLogById(Long noteId);
}
