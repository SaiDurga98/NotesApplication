package com.techie.notes.service;


import com.techie.notes.models.Note;

import java.util.List;


public interface NoteService {

    Note createNoteForUser(String username, String content);

    Note updateNoteForUser(Long noteId, String username, String content);

    void deleteNoteForUser(Long noteId, String username);

    List<Note> getNotesForUser(String username);

}
