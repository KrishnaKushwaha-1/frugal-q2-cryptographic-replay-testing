
package com.frugal.security;

public class App {

    public static void main(String[] args) throws Exception {

        MockApiServer server = new MockApiServer();

        server.start();

        Runtime.getRuntime().addShutdownHook(
                new Thread(() -> {
                    server.stop();
                    System.out.println(
                            "Mock API server stopped."
                    );
                })
        );
    }
}
