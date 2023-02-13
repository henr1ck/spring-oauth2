package br.edu.ifpi.resourceserver.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class GameRequestBody {
    private String name;
    private LocalDate release;
}
