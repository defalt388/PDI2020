package com.PSN.crudPDI.controller

import com.PSN.crudPDI.model.PSN4
import com.PSN.crudPDI.repository.PSRepository
import com.PSN.crudPDI.service.PService
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import org.springframework.web.servlet.support.ServletUriComponentsBuilder

@RestController
@RequestMapping("/CrudPDI")
class PSController(private val psRepository: PSRepository, private val pservice: PService)
{
    @GetMapping("/allPlayers")
    fun getAllPlayers(): MutableIterable<PSN4> =
            pservice.getAllPlayers()

    @GetMapping("/idPlayer/{id}")
    fun getById(@PathVariable id: Long): ResponseEntity<PSN4>
    {
        val play = pservice.getPlayerById(id)
        return ResponseEntity.ok(play)
    }

    @PostMapping
    fun addPlayer(
            @RequestBody  ps: PSN4
    ): ResponseEntity<Any?>
    {
        val psId = pservice.createNewPlayer(ps)
        val location = ServletUriComponentsBuilder
                .fromCurrentRequest()
                .path("/{psId}")
                .build(psId)
        return ResponseEntity.created(location).build()
    }

    @PatchMapping("/PSN/nome/{id}")
    fun UpdateName(@PathVariable id: Long, @RequestBody name: PSN4): ResponseEntity<Any?>
    {
        pservice.UpdateName(id, name)
        return ResponseEntity.noContent().build()
    }

    @PatchMapping("/PSN/genero/{id}")
    fun UpdateG(@PathVariable id: Long, @RequestBody g: PSN4): ResponseEntity<Any?>
    {
        pservice.UpdateGenero(id, g)
        return ResponseEntity.noContent().build()
    }

    @PatchMapping("/PSN/IdTag/{id}")
    fun UpdateIdTag(@PathVariable id: Long, @RequestBody tag: PSN4): ResponseEntity<Any?>
    {
        pservice.UpdateIdTag(id, tag)
        return ResponseEntity.noContent().build()
    }

    @PatchMapping("/PSN/jogos/{id}")
    fun UpdateJogos(@PathVariable id: Long, @RequestBody jogos: PSN4): ResponseEntity<Any?>
    {
        pservice.UpdateJogos(id, jogos)
        return ResponseEntity.noContent().build()
    }

    @PatchMapping("/PSN/trofeu/{id}")
    fun UpdateTrofeu(@PathVariable id: Long, @RequestBody trofeu: PSN4): ResponseEntity<Any?>
    {
        pservice.UpdateTrofeu(id, trofeu)
        return ResponseEntity.noContent().build()
    }


    @PatchMapping("/PSN/avaliacao/{id}")
    fun UpdateAvaliacao(@PathVariable id: Long, @RequestBody avaliacao: PSN4): ResponseEntity<Any?>
    {
        pservice.UpdateAvaliacao(id, avaliacao)
        return ResponseEntity.noContent().build()
    }

    @DeleteMapping("/delPSN/{id}")
    fun deletePlayerById(@PathVariable(value = "id") id: Long): ResponseEntity<Any?>
    {
        pservice.deletePlayerById(id)
        return ResponseEntity.ok().build()
    }

}
