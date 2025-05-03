package com.techie.notes.repository;

import com.techie.notes.models.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AuditRepository extends JpaRepository<AuditLog, Long> {


    List<AuditLog> findByNoteId(Long noteId);
}
