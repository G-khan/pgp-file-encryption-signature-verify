plugins {
    kotlin("jvm") version "1.4.32"
    application
}

group = "com.gokhana"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

kotlin {
    sourceSets["main"].apply {
        kotlin.srcDir("src/main/kotlin")
    }
}
application {
    mainClass.set("securepgp.PGPApplicationKt")
}

dependencies {
    implementation(platform("org.jetbrains.kotlin:kotlin-bom"))
    implementation(kotlin("stdlib"))
    implementation("org.bouncycastle:bcprov-jdk15on:1.51")
    implementation("org.bouncycastle:bcpg-jdk15on:1.51")
}
