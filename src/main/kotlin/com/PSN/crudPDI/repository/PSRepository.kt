package com.PSN.crudPDI.repository

import com.PSN.crudPDI.model.PSN4
import org.springframework.data.repository.CrudRepository
import org.springframework.stereotype.Repository

//Essa é a classe DAO, com a extensão do crud todos os métodos CRUD são importados
@Repository
interface PSRepository : CrudRepository<PSN4, Long>
{
    fun findPlayerByNomeAndIdtag(nome: String, idtag: String): PSN4
    fun findPlayerByNome(nome: String): PSN4

}