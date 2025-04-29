# lib-rust
the corollary to github.com/derecalliance/lib-java , for rust

## Prerequisites
1. Clone and build the [DeRec cryptography library repository](https://github.com/derecalliance/cryptography)

## Library setup in IntelliJ
1. Clone the repo
2. Open the project in IntelliJ
3. Add the native cryptography library (ex: the `.dylib` file) to this project's file structure. Make sure to modify the cryptography library under Modules > Dependencies. Instructions to do this can be found [here](https://www.jetbrains.com/help/idea/library.html#add_classes_to_libraries).
4. In the file strucure on the screen, navigate to `impl/src/generated`
5. Right-click the `generated` folder, and select "Mark Directory As" > "Unmark as Sources Root"
6. Then, the folders within `generated` should expand. Right-click on `impl/src/generated/java` and select "Mark
   Directory As" > "Sources Root".
7. Mark `generated` as sources root as well by right-clicking on `impl/src/generated` and selecting Mark Directory
   As" > "Sources Root". Now, both `generated` and `java` folders should be marked as sources roots (the folder icon turns blue).
8. In the terminal, navigate to the root directory `dereclib`  and run `mvn clean compile package install`
9. In the terminal, `dereclib/api` and run `mvn clean compile package install`
10. In the terminal, `dereclib/impl` and run `mvn clean compile package install`

## Formatting Files
1. Run `mvn validate` in the `impl` directory to format all files if changes are made.
