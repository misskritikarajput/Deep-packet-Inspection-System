package com.dpi.engine;

import com.dpi.rules.RuleManager;

import java.util.ArrayList;
import java.util.List;

/** Parses the DPI engine's command-line arguments. */
public final class CliOptions {

    public String inputPath;
    public String outputPath;
    public boolean simpleMode = false;
    public int numLbs = 2;
    public int numFps = 4;
    public final RuleManager rules = new RuleManager();

    public static CliOptions parse(String[] args) {
        CliOptions opts = new CliOptions();
        List<String> positional = new ArrayList<>();

        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case "--simple":
                    opts.simpleMode = true;
                    break;
                case "--block-app":
                    opts.rules.blockApp(requireValue(args, ++i, "--block-app"));
                    break;
                case "--block-ip":
                    opts.rules.blockIp(requireValue(args, ++i, "--block-ip"));
                    break;
                case "--block-domain":
                    opts.rules.blockDomain(requireValue(args, ++i, "--block-domain"));
                    break;
                case "--lbs":
                    opts.numLbs = Integer.parseInt(requireValue(args, ++i, "--lbs"));
                    break;
                case "--fps":
                    opts.numFps = Integer.parseInt(requireValue(args, ++i, "--fps"));
                    break;
                case "-h":
                case "--help":
                    printUsage();
                    System.exit(0);
                    break;
                default:
                    positional.add(a);
            }
        }

        if (positional.size() < 2) {
            printUsage();
            throw new IllegalArgumentException("input and output pcap paths are required");
        }
        opts.inputPath = positional.get(0);
        opts.outputPath = positional.get(1);
        return opts;
    }

    private static String requireValue(String[] args, int idx, String flag) {
        if (idx >= args.length) {
            throw new IllegalArgumentException(flag + " requires a value");
        }
        return args[idx];
    }

    private static void printUsage() {
        System.out.println("Usage: dpi-engine <input.pcap> <output.pcap> [options]\n"
                + "\n"
                + "Options:\n"
                + "  --simple                 Use the single-threaded engine\n"
                + "  --block-app <name>       Block an application (e.g. YouTube, TikTok)\n"
                + "  --block-ip <ip>          Block a source IP address\n"
                + "  --block-domain <substr>  Block any SNI/Host containing this substring\n"
                + "  --lbs <n>                Number of Load Balancer threads (multi-threaded mode)\n"
                + "  --fps <n>                Total number of Fast Path threads (multi-threaded mode)\n"
                + "  -h, --help               Show this help message\n");
    }
}
