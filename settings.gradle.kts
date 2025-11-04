/*
 * Copyright (c) 2024 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        mavenLocal()
        google()
        mavenCentral()
        maven {
            name = "affinitiquest-dev"
            url = uri("https://pkgs.dev.azure.com/affinitiquest/AffinitiQuest/_packaging/affinitiquest-dev/maven/v1")
            credentials {
                username = getPropertyFromFile("maven.username")
                password = getPropertyFromFile("maven.password")
            }
        }
        maven {
            url = uri("https://s01.oss.sonatype.org/content/repositories/snapshots/")
            mavenContent { snapshotsOnly() }
        }
    }
}

// Helper function to read from a properties file.
fun getPropertyFromFile(key: String): String? {
    val propertyFile = file("maven.properties")
    if(propertyFile.exists()) {
        val properties = java.util.Properties()
        propertyFile.inputStream().use { properties.load(it) }
        return properties.getProperty(key)
    }
    return null
}

rootProject.name = "eudi-lib-android-wallet-core"
include(":wallet-core")
