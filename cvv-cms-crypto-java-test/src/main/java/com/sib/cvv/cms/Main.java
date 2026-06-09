package com.sib.cvv.cms;

import java.io.PrintStream;

import com.openfintechlab.cms.CMSDecrypt;
import com.openfintechlab.cms.CMSEncrypt;

public final class Main {
    private static final String CMS_DECRYPT_COMMAND = "cms-decrypt";
    private static final String CMS_ENCRYPT_COMMAND = "cms-encrypt";

    private Main() {
    }

    public static void main(String[] args) {
        int exitCode = run(args, System.out, System.err);
        if (exitCode != 0) {
            System.exit(exitCode);
        }
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        if (args.length != 3) {
            printUsage(err);
            return 1;
        }

        try {
            if (CMS_ENCRYPT_COMMAND.equals(args[0])) {
                out.println(CMSEncrypt.encryptToCmsBase64(args[1], args[2]));
                return 0;
            }

            if (CMS_DECRYPT_COMMAND.equals(args[0])) {
                out.println(CMSDecrypt.decryptFromCmsBase64(args[1], args[2]));
                return 0;
            }

            printUsage(err);
            return 1;
        } catch (Exception ex) {
            err.println(args[0] + " failed: " + ex.getMessage());
            return 2;
        }
    }

    private static void printUsage(PrintStream err) {
        err.println("Usage:");
        err.println("  cms-encrypt <text> <public-key-pem>");
        err.println("  cms-decrypt <cipher-text> <private-key-pem>");
    }
}
