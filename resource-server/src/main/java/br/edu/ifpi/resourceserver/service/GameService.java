package br.edu.ifpi.resourceserver.service;

import br.edu.ifpi.resourceserver.domain.Game;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface GameService {
    Game findById(Long id);
    Page<Game> findAll(Pageable pageable);
    Game save(Game game);
    void deleteById(Long id);
    void update(Long id, Game game);
}
