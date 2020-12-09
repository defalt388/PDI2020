import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
	id("org.springframework.boot") version "2.3.2.RELEASE"
	id("io.spring.dependency-management") version "1.0.9.RELEASE"
	kotlin("jvm") version "1.3.72"
	kotlin("plugin.spring") version "1.3.72"
	kotlin("plugin.jpa") version "1.3.72"
}

group = "PSN"
version = "0.0.1-SNAPSHOT"
java.sourceCompatibility = JavaVersion.VERSION_1_8

repositories {
	mavenCentral()
}

dependencies {
	implementation("org.springframework.boot:spring-boot-starter-data-jdbc")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
	implementation("org.springframework.boot:spring-boot-starter-oauth2-resource-server")
	implementation("org.projectlombok:lombok:1.18.8")
	implementation("io.springfox:springfox-swagger2:2.9.2")
	implementation("io.springfox:springfox-swagger-ui:2.9.2")
	implementation ("com.auth0:java-jwt:3.11.0")
	implementation("com.microsoft.sqlserver:mssql-jdbc")
	implementation("org.mindrot:jbcrypt:0.4")
	implementation("org.springframework.boot:spring-boot-starter-web")
	implementation ("io.jsonwebtoken:jjwt:0.9.1")
	implementation("com.fasterxml.jackson.module:jackson-module-kotlin")
	implementation("org.postgresql:postgresql")
	implementation("org.flywaydb:flyway-core")
	implementation("org.jetbrains.kotlin:kotlin-reflect")
	implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8")
	developmentOnly("org.springframework.boot:spring-boot-devtools")
	runtimeOnly("com.h2database:h2")
	runtimeOnly("mysql:mysql-connector-java")
	testImplementation("org.springframework.boot:spring-boot-starter-test") {
		exclude(group = "org.junit.vintage", module = "junit-vintage-engine")
	}
	testImplementation("io.rest-assured:rest-assured:3.1.1")
	testImplementation ("io.rest-assured:json-path:3.1.1")
	testImplementation("io.rest-assured:xml-path:3.1.1")
	testImplementation("io.rest-assured:json-schema-validator:3.1.1")
	testImplementation("org.assertj:assertj-core:3.16.1")
	testImplementation ("org.testcontainers:testcontainers:1.14.3")
}
tasks["check"].dependsOn("integrationTest")

tasks.withType<Test> {
	useJUnitPlatform()
}

sourceSets {
	create("integrationTest") {
		withConvention(org.jetbrains.kotlin.gradle.plugin.KotlinSourceSet::class) {
			kotlin.srcDir("src/integrationTest/kotlin")
			resources.srcDir("src/integrationTest/resources")
			compileClasspath += sourceSets["main"].output + configurations["testRuntimeClasspath"]
			runtimeClasspath += output + compileClasspath + sourceSets["test"].runtimeClasspath
		}
	}
}

task<Test>("integrationTest") {
	description = "Runs the integration tests"
	group = "verification"
	testClassesDirs = sourceSets["integrationTest"].output.classesDirs
	classpath = sourceSets["integrationTest"].runtimeClasspath
	mustRunAfter(tasks["test"])
}

tasks["check"].dependsOn("integrationTest")

tasks.withType<KotlinCompile> {
	kotlinOptions {
		freeCompilerArgs = listOf("-Xjsr305=strict")
		jvmTarget = "1.8"
	}
}
