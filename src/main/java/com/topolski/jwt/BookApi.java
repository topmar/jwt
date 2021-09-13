package com.topolski.jwt;

import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/books")
public class BookApi {
    private final List<String> bookList;
    public BookApi() {
        this.bookList = new ArrayList<>();
        bookList.add("Spring Boot 2");
        bookList.add("Spring in Action");
    }

    @GetMapping
    public List<String> getBookList() {
        return bookList;
    }

    @PostMapping
    public void addBook (@RequestBody String book) {
        this.bookList.add(book);
    }
}
