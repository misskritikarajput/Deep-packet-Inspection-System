package com.dpi;

import com.dpi.engine.CliOptions;
import com.dpi.engine.DPIMultiThreaded;
import com.dpi.engine.DPISimple;

/**
 * Command-line entry point for the DPI Engine.
 *
 * Usage:
 *   java -jar dpi-engine.jar &lt;input.pcap&gt; &lt;output.pcap&gt; [options]
 *
 * Options:
 *   --simple                 Use the single-threaded engine
 *   --block-app &lt;name&gt;       Block an application (e.g. YouTube, TikTok)
 *   --block-ip &lt;ip&gt;          Block a source IP address
 *   --block-domain &lt;substr&gt;  Block any SNI/Host containing this substring
 *   --lbs &lt;n&gt;                Number of Load Balancer threads (multi-threaded mode)
 *   --fps &lt;n&gt;                Total number of Fast Path threads (multi-threaded mode)
 */
public final class Main {

    public static void main(String[] args) {
        try {
            CliOptions opts = CliOptions.parse(args);

            if (opts.simpleMode) {
                new DPISimple(opts.rules).run(opts.inputPath, opts.outputPath);
            } else {
                new DPIMultiThreaded(opts.rules, opts.numLbs, opts.numFps)
                        .run(opts.inputPath, opts.outputPath);
            }
        } catch (IllegalArgumentException e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        } catch (Exception e) {
            System.err.println("Fatal error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
