package com.PSN.crudPDI.app

import org.springframework.boot.autoconfigure.EnableAutoConfiguration
import org.springframework.boot.autoconfigure.domain.EntityScan
import org.springframework.boot.context.properties.ConfigurationPropertiesScan
import org.springframework.boot.runApplication
import org.springframework.context.annotation.ComponentScan
import org.springframework.data.jpa.repository.config.EnableJpaRepositories

@EnableAutoConfiguration
@ComponentScan(basePackages = ["com.PSN.crudPDI"])
@EnableJpaRepositories(basePackages = ["com.PSN.crudPDI.repository"])
@EntityScan(basePackages = ["com.PSN.crudPDI.model"])
class CrudPsnApplication

fun main(args: Array<String>) {
    runApplication<CrudPsnApplication>(*args)
}
