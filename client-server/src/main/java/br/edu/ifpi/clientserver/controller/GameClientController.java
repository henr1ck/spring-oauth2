package br.edu.ifpi.clientserver.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

@Log4j2
@RestController
@RequiredArgsConstructor
@RequestMapping(path = "/")
public class GameClientController {

    private final WebClient webClient;

    @GetMapping(path = "/games")
    public String inspect(){
        String result = webClient.get()
                .uri("http://localhost:8081/api/game")
                .attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction
                        .clientRegistrationId("xpto-client-credentials"))
                .retrieve()
                .bodyToMono(String.class)
                .block();

        log.info(result);
        return result;
    }
}
