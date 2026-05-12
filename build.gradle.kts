plugins {
    kotlin("jvm") version "2.1.20"
    application
}

group = "fridalink"
version = "0.1.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation(kotlin("stdlib"))
    implementation("net.portswigger.burp.extensions:montoya-api:2026.2")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.18.3")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.18.3")
    // PDF report generation
    implementation("org.apache.pdfbox:pdfbox:3.0.3")
}

kotlin {
    jvmToolchain(21)
}

application {
    mainClass = "fridalink.FridaLinkExtension"
}

tasks.jar {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    manifest {
        attributes["Main-Class"] = "fridalink.FridaLinkExtension"
    }
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
}
