package br.edu.ifpi.resourceserver.controller;

import br.edu.ifpi.resourceserver.domain.Game;
import br.edu.ifpi.resourceserver.domain.GameRequestBody;
import br.edu.ifpi.resourceserver.service.GameService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.concurrent.TimeUnit;

@Log4j2
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
    public ResponseEntity<Page<Game>> findAll(HttpServletRequest request, Pageable pageable){
        Page<Game> gamePage = gameService.findAll(pageable);

        log.info("if-none-match: {}", request.getHeader("if-none-match"));
        return ResponseEntity.status(HttpStatus.OK)
                .cacheControl(CacheControl.maxAge(30, TimeUnit.SECONDS))
                .body(gamePage);
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
