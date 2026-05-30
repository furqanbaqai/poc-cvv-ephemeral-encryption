package com.sib.cvv;

import com.openfintechlab.jwe.Reveal;
import com.openfintechlab.jwe.model.RevealRequest;
import com.openfintechlab.jwe.util.JsonUtil;

public class Main {
    private static final String COMMAND_REVEAL = "reveal";
    private static final String OPTION_DEBUG = "debug";

    public static void main(String[] args) {
        try {
            if (!isValidArguments(args)) {
                printUsage();
                System.exit(1);
            }

            boolean debug = args.length == 2;
            RevealRequest revealRequest = Reveal.buildRevealRequest(debug);
            System.out.println(JsonUtil.toMinifiedJson(revealRequest));
        } catch (Exception exception) {
            System.err.println("Error: " + exception.getMessage());
            System.exit(1);
        }
    }

    private static boolean isValidArguments(String[] args) {
        if (args.length < 1 || args.length > 2) {
            return false;
        }

        if (!COMMAND_REVEAL.equals(args[0])) {
            return false;
        }

        return args.length != 2 || OPTION_DEBUG.equals(args[1]);
    }

    private static void printUsage() {
        System.err.println("Usage: java -jar cvv-encryption-java.jar <COMMAND> [OPTIONS]");
        System.err.println();
        System.err.println("Commands:");
        System.err.println("  reveal [debug]    Generate ephemeral RSA key pair and output request JSON");
        System.err.println("                    Include 'debug' to emit private key PEM");
        System.err.println();
        System.err.println("Examples:");
        System.err.println("  java -jar cvv-encryption-java.jar reveal");
        System.err.println("  java -jar cvv-encryption-java.jar reveal debug");
    }
}
