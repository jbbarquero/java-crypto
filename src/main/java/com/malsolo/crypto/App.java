package com.malsolo.crypto;

import java.util.stream.Stream;

/**
 * Hello world!
 *
 */
public class App {
    public static void main( String[] args ) {
        Stream.of(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
                .filter(n -> n % 2 == 0)
                .map(String::valueOf)
                .forEach(System.out::println);

        System.out.println( "Hello World!" );
    }
}
