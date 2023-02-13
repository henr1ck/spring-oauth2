package br.edu.ifpi.resourceserver.controller;

import br.edu.ifpi.resourceserver.domain.Game;
import br.edu.ifpi.resourceserver.domain.GameRequestBody;
import br.edu.ifpi.resourceserver.service.GameService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = "/api/game")
@RequiredArgsConstructor
public class GameController {

    private final GameService gameService;
    private final ModelMapper mapper;

    @GetMapping(path = "/{id}")
    @ResponseStatus(HttpStatus.OK)
    public Game findById(@PathVariable Long id){
        return gameService.findById(id);
    }

    @GetMapping
    @ResponseStatus(HttpStatus.OK)
    public Page<Game> findAll(Pageable pageable){
        return gameService.findAll(pageable);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Game save(@RequestBody GameRequestBody gameRequestBody){
        Game game = convertToDomainObject(gameRequestBody);
        return gameService.save(game);
    }

    @DeleteMapping(path = "/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable Long id){
        gameService.deleteById(id);
    }

    @PutMapping(path = "/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void update(@PathVariable Long id ,@RequestBody GameRequestBody gameRequestBody){
        Game game = convertToDomainObject(gameRequestBody);
        gameService.update(id, game);
    }

    private Game convertToDomainObject(GameRequestBody gameRequestBody){
        return mapper.map(gameRequestBody, Game.class);
    }
}
