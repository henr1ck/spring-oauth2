package br.edu.ifpi.resourceserver.service;

import br.edu.ifpi.resourceserver.domain.Game;
import br.edu.ifpi.resourceserver.repository.GameRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
public class GameServiceImpl implements GameService{

    private final GameRepository repository;

    @Override
    public Game findById(Long id) {
        return repository.findById(id).orElseThrow(
                () -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Game not found!")
        );
    }

    @Override
    public Page<Game> findAll(Pageable pageable) {
        return repository.findAll(pageable);
    }

    @Override
    public Game save(Game game) {
        return repository.save(game);
    }

    @Override
    public void deleteById(Long id) {
        repository.delete(findById(id));
    }

    @Override
    public void update(Long id, Game game) {
        Game gameFound = findById(id);
        game.setId(gameFound.getId());

        repository.save(game);
    }
}
