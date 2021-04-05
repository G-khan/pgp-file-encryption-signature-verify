plugins {
    kotlin("jvm") version "1.4.32"
}

group = "com.gokhana"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation(kotlin("stdlib"))
    implementation(kotlin("stdlib"))
    implementation("org.bouncycastle:bcprov-jdk15on:1.51")
    implementation("org.bouncycastle:bcpg-jdk15on:1.51")
}
