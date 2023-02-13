package br.edu.ifpi.resourceserver.repository;

import br.edu.ifpi.resourceserver.domain.Game;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface GameRepository extends JpaRepository<Game, Long> {

}
