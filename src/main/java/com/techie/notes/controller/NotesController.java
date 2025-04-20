package com.techie.notes.controller;


import com.techie.notes.models.Note;
import com.techie.notes.service.NoteService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/notes")
public class NotesController {

    @Autowired
    private NoteService noteService;

    @PostMapping
    public Note createNote(@RequestBody String content, @AuthenticationPrincipal UserDetails userDetails) {
        String username = userDetails.getUsername();
        System.out.println("UserDetails: " + username);
        return noteService.createNoteForUser(username, content);

    }

    @GetMapping
    public List<Note> getUserNotes(@AuthenticationPrincipal UserDetails userDetails) {
        String userName = userDetails.getUsername();
        System.out.println("UserDetails to getNotesForUser: " + userName);
        return noteService.getNotesForUser(userName);

    }

    @PutMapping("/{noteId}")
    public Note updateNote(@PathVariable Long noteId, @RequestBody String content, @AuthenticationPrincipal UserDetails userDetails) {
        String userName = userDetails.getUsername();
        System.out.println("UserDetails to update Notes for user: " + userName);
        return noteService.updateNoteForUser(noteId, userName, content);
    }

    @DeleteMapping("/{noteId}")
    public void deleteNote(@PathVariable Long noteId, @AuthenticationPrincipal UserDetails userDetails) {
        String userName = userDetails.getUsername();
        System.out.println("UserDetails to delete Notes for user: " + userName);
        noteService.deleteNoteForUser(noteId, userName);
    }


}
