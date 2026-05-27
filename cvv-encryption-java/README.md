# cvv-encryption-java

Minimal Maven Java project for the CVV encryption proof of concept.

## Prerequisites

- Java 17 or later
- Apache Maven 3.8 or later

Verify the tools are available:

```sh
java -version
mvn -version
```

## Project Structure

```text
cvv-encryption-java/
  pom.xml
  src/main/java/com/sib/cvv/Main.java
```

## Compile

From the `cvv-encryption-java` directory:

```sh
mvn compile
```

## Run

Run the application with Maven:

```sh
mvn exec:java -Dexec.mainClass="com.sib.cvv.Main"
```

Alternatively, compile first and run with `java`:

```sh
mvn compile
java -cp target/classes com.sib.cvv.Main
```

Expected output:

```text
Hello World!
```

## Package

Build the project artifact:

```sh
mvn package
```

The generated artifact is created under the `target/` directory.

## Clean

Remove build outputs:

```sh
mvn clean
```
