@echo off
setlocal enabledelayedexpansion

echo ========================================
echo Creating Maven Java Project: cvv-encryption-java
echo ========================================
echo.

REM Set project variables
set PROJECT_NAME=cvv-encryption-java
set GROUP_ID=com.encryption
set ARTIFACT_ID=%PROJECT_NAME%
set PACKAGE=com.encryption.cvv

REM Create project directory structure
echo Creating directory structure...
mkdir %PROJECT_NAME% 2>nul
cd %PROJECT_NAME%

REM Create standard Maven directories
mkdir src\main\java\com\encryption\cvv 2>nul
mkdir src\main\resources 2>nul
mkdir src\test\java\com\encryption\cvv 2>nul
mkdir src\test\resources 2>nul

REM Create minimal pom.xml
echo Creating pom.xml...
(
echo ^<?xml version="1.0" encoding="UTF-8"?^>
echo ^<project xmlns="http://maven.apache.org/POM/4.0.0"
echo          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
echo          xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
echo          http://maven.apache.org/xsd/maven-4.0.0.xsd"^>
echo     ^<modelVersion^>4.0.0^</modelVersion^>
echo.
echo     ^<groupId^>%GROUP_ID%^</groupId^>
echo     ^<artifactId^>%ARTIFACT_ID%^</artifactId^>
echo     ^<version^>1.0-SNAPSHOT^</version^>
echo     ^<packaging^>jar^</packaging^>
echo.
echo     ^<name^>CVV Encryption Java Project^</name^>
echo     ^<description^>Simple Maven project with Hello World^</description^>
echo.
echo     ^<properties^>
echo         ^<maven.compiler.source^>11^</maven.compiler.source^>
echo         ^<maven.compiler.target^>11^</maven.compiler.target^>
echo         ^<project.build.sourceEncoding^>UTF-8^</project.build.sourceEncoding^>
echo     ^</properties^>
echo.
echo     ^<build^>
echo         ^<plugins^>
echo             ^<plugin^>
echo                 ^<groupId^>org.apache.maven.plugins^</groupId^>
echo                 ^<artifactId^>maven-compiler-plugin^</artifactId^>
echo                 ^<version^>3.11.0^</version^>
echo             ^</plugin^>
echo             ^<plugin^>
echo                 ^<groupId^>org.apache.maven.plugins^</groupId^>
echo                 ^<artifactId^>maven-jar-plugin^</artifactId^>
echo                 ^<version^>3.3.0^</version^>
echo                 ^<configuration^>
echo                     ^<archive^>
echo                         ^<manifest^>
echo                             ^<mainClass^>com.encryption.cvv.Main^</mainClass^>
echo                         ^</manifest^>
echo                     ^</archive^>
echo                 ^</configuration^>
echo             ^</plugin^>
echo         ^</plugins^>
echo     ^</build^>
echo ^</project^>
) > pom.xml

REM Create Main.java with Hello World (using echo with parentheses properly escaped)
echo Creating Main.java...
echo package com.encryption.cvv; > src\main\java\com\encryption\cvv\Main.java
echo. >> src\main\java\com\encryption\cvv\Main.java
echo public class Main { >> src\main\java\com\encryption\cvv\Main.java
echo     public static void main(String[] args) { >> src\main\java\com\encryption\cvv\Main.java
echo         System.out.println("Hello World!"); >> src\main\java\com\encryption\cvv\Main.java
echo     } >> src\main\java\com\encryption\cvv\Main.java
echo } >> src\main\java\com\encryption\cvv\Main.java

REM Create a simple test class
echo Creating placeholder test class...
echo package com.encryption.cvv; > src\test\java\com\encryption\cvv\MainTest.java
echo. >> src\test\java\com\encryption\cvv\MainTest.java
echo import org.junit.jupiter.api.Test; >> src\test\java\com\encryption\cvv\MainTest.java
echo import static org.junit.jupiter.api.Assertions.*; >> src\test\java\com\encryption\cvv\MainTest.java
echo. >> src\test\java\com\encryption\cvv\MainTest.java
echo public class MainTest { >> src\test\java\com\encryption\cvv\MainTest.java
echo     @Test >> src\test\java\com\encryption\cvv\MainTest.java
echo     public void testDummy() { >> src\test\java\com\encryption\cvv\MainTest.java
echo         assertTrue(true); >> src\test\java\com\encryption\cvv\MainTest.java
echo     } >> src\test\java\com\encryption\cvv\MainTest.java
echo } >> src\test\java\com\encryption\cvv\MainTest.java

REM Create simple README
echo Creating README.md...
echo # CVV Encryption Java Project > README.md
echo. >> README.md
echo ## Overview >> README.md
echo Simple Maven project with Hello World example. >> README.md
echo. >> README.md
echo ## Build Instructions >> README.md
echo. >> README.md
echo ### Prerequisites >> README.md
echo - Java 11 or higher >> README.md
echo - Maven 3.6 or higher >> README.md
echo. >> README.md
echo ### Building the Project >> README.md
echo ```bash >> README.md
echo mvn clean compile >> README.md
echo ``` >> README.md
echo. >> README.md
echo ### Creating JAR File >> README.md
echo ```bash >> README.md
echo mvn clean package >> README.md
echo ``` >> README.md
echo. >> README.md
echo ### Running the Application >> README.md
echo ```bash >> README.md
echo java -jar target/cvv-encryption-java-1.0-SNAPSHOT.jar >> README.md
echo ``` >> README.md

REM Create build script
echo Creating build.bat...
echo @echo off > build.bat
echo echo ======================================== >> build.bat
echo echo Building CVV Encryption Project >> build.bat
echo echo ======================================== >> build.bat
echo echo. >> build.bat
echo echo Cleaning previous builds... >> build.bat
echo call mvn clean >> build.bat
echo echo. >> build.bat
echo echo Compiling source code... >> build.bat
echo call mvn compile >> build.bat
echo echo. >> build.bat
echo echo Creating JAR file... >> build.bat
echo call mvn package >> build.bat
echo echo. >> build.bat
echo echo ======================================== >> build.bat
echo echo Build Complete! >> build.bat
echo echo JAR file created in target directory >> build.bat
echo echo ======================================== >> build.bat
echo echo. >> build.bat
echo echo To run the application: >> build.bat
echo echo java -jar target/cvv-encryption-java-1.0-SNAPSHOT.jar >> build.bat
echo echo. >> build.bat
echo pause >> build.bat

REM Create run script
echo Creating run.bat...
echo @echo off > run.bat
echo echo Running CVV Encryption Java Project... >> run.bat
echo echo. >> run.bat
echo java -jar target/cvv-encryption-java-1.0-SNAPSHOT.jar >> run.bat
echo echo. >> run.bat
echo pause >> run.bat

REM Create a simple maven wrapper script
echo Creating maven-run.bat...
echo @echo off > maven-run.bat
echo mvn exec:java -Dexec.mainClass="com.encryption.cvv.Main" >> maven-run.bat
echo pause >> maven-run.bat

echo.
echo ========================================
echo Project Created Successfully!
echo ========================================
echo Project Name: %PROJECT_NAME%
echo Location: %CD%
echo.
echo Project Structure:
echo %PROJECT_NAME%/
echo   ├── pom.xml
echo   ├── build.bat
echo   ├── run.bat
echo   ├── maven-run.bat
echo   ├── README.md
echo   └── src/
echo       ├── main/
echo       │   └── java/com/encryption/cvv/
echo       │       └── Main.java
echo       └── test/
echo           └── java/com/encryption/cvv/
echo               └── MainTest.java
echo.
echo Next Steps:
echo 1. cd %PROJECT_NAME%
echo 2. Run build.bat to compile and create JAR
echo 3. Run run.bat to execute the Hello World application
echo.
echo OR use Maven commands directly:
echo - mvn clean compile     (compile only)
echo - mvn clean package     (create JAR)
echo - mvn exec:java -Dexec.mainClass="com.encryption.cvv.Main" (run directly)
echo.
echo ========================================

cd ..