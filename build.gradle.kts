group = "com.katiearose"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation(platform("org.jetbrains.kotlin:kotlin-bom"))
    implementation(kotlin("stdlib"))
    testImplementation(kotlin("test-junit5"))
    testImplementation(platform("org.junit:junit-bom:5.7.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}

plugins {
    `java-library`
    kotlin("jvm") version "1.6.10"
    `maven-publish`
    application
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
}

tasks.jar {
    dependsOn("test")
    manifest {
        attributes(
            "Implementation-Title" to project.name,
            "Implementation-Version" to project.version
        )
    }
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            groupId = "com.katiearose"
            artifactId = "reasonably-easy-cryptography"
            version = "1.0.0"
            from(components["java"])
            pom {
                name.set("Reasonably Easy Cryptography")
                description.set("Usable cryptography for everyone!")
                licenses {
                    license {
                        name.set("GNU GENERAL PUBLIC LICENSE, Version 3.0")
                    }
                    license {
                        name.set("GNU LESSER GENERAL PUBLIC LICENSE, Version 3.0")
                    }
                }
                developers {
                    developer {
                        id.set("KiARC")
                        name.set("Katherine Rose")
                        email.set("katiearose@protonmail.com")
                    }
                }
            }
        }
    }
}