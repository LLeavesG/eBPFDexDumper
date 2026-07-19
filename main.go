//go:build arm64

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	cli "github.com/urfave/cli/v2"
	"golang.org/x/sys/unix"
)

// Remove core logic from this file; CLI only remains.

func main() {
	// log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetFlags(0)
	log.SetOutput(os.Stdout)

	app := &cli.App{
		Name:  "eBPFDexDumper",
		Usage: "Dump in-memory DEX/method bytecode or native .so libraries, and fix the dumped files",
		// Custom help template shows concise top-level info and compact subcommand details
		CustomAppHelpTemplate: `NAME:
   {{.Name}} - {{.Usage}}

USAGE:
   {{.HelpName}} [command] [options]

COMMANDS:
{{range .VisibleCommands}}   {{index .Names 0}}  {{.Usage}}
{{end}}

SUBCOMMANDS:
{{range .VisibleCommands}}
{{.Name}} - {{.Usage}}
  Usage: {{$.HelpName}} {{.Name}} [options]
  Description: {{.Description}}
  Options:
   {{range .VisibleFlags}}{{.}}
   {{end}}

{{end}}`,
		HideHelpCommand: true,
		Commands: []*cli.Command{
			{
				Name:        "dump",
				Usage:       "Start eBPF-based DEX dumper",
				Description: "Attach uprobes to libart and stream DEX/method events; provide either --uid or --name to filter.",
				CustomHelpTemplate: `NAME:
   {{.HelpName}} - {{.Usage}}

USAGE:
   {{.HelpName}} [command options]

DESCRIPTION:
   {{.Description}}

OPTIONS:
   {{range .VisibleFlags}}{{.}}
   {{end}}`,
				Flags: []cli.Flag{
					&cli.Uint64Flag{Name: "uid", Aliases: []string{"u"}, Usage: "Filter by UID (alternative to --name)"},
					&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "Android package name to derive UID (alternative to --uid)"},
					&cli.StringFlag{Name: "libart", Aliases: []string{"l"}, Usage: "Path to libart.so (target device)", Value: "/apex/com.android.art/lib64/libart.so", DefaultText: "/apex/com.android.art/lib64/libart.so"},
					&cli.StringFlag{Name: "out", Aliases: []string{"o", "output"}, Usage: "Output directory on device", Value: "/data/local/tmp/dex_out", DefaultText: "/data/local/tmp/dex_out"},
					&cli.BoolFlag{Name: "trace", Aliases: []string{"t"}, Usage: "Print executed methods in real time during dumping"},
					&cli.BoolFlag{Name: "clean-oat", Aliases: []string{"c"}, Usage: "Remove /data/app/.../oat folders of target app(s) before dumping", Value: true},
					&cli.BoolFlag{Name: "auto-fix", Aliases: []string{"f"}, Usage: "Automatically fix DEX files after dumping", Value: true},
					&cli.BoolFlag{Name: "no-clean-oat", Usage: "Disable automatic oat cleaning"},
					&cli.BoolFlag{Name: "no-auto-fix", Usage: "Disable automatic DEX fixing"},
					&cli.Uint64Flag{Name: "execute-offset", Usage: "Manual offset for art::interpreter::Execute function (hex value, e.g. 0x12345)"},
					&cli.Uint64Flag{Name: "nterp-offset", Usage: "Manual offset for ExecuteNterpImpl function (hex value, e.g. 0x12345)"},
				},
				Action: func(c *cli.Context) error {
					uid := uint32(c.Uint64("uid"))
					pkgName := c.String("name")
					libArtPath := c.String("libart")
					outputDir := c.String("out")
					trace := c.Bool("trace")
					cleanOat := c.Bool("clean-oat") && !c.Bool("no-clean-oat")
					autoFix := c.Bool("auto-fix") && !c.Bool("no-auto-fix")
					executeOffset := c.Uint64("execute-offset")
					nterpOffset := c.Uint64("nterp-offset")

					if err := os.MkdirAll(outputDir, 0755); err != nil {
						return fmt.Errorf("failed to create output directory %s: %w", outputDir, err)
					}

					if uid == 0 && pkgName == "" {
						return fmt.Errorf("either --uid or --name must be provided")
					}
					if uid == 0 && pkgName != "" {
						// Resolve UID by package name
						resolved, err := LookupUIDByPackageName(pkgName)
						if err != nil {
							return err
						}
						uid = resolved
						log.Printf("[+] Resolved UID %d from package %q", uid, pkgName)
					}

					// Optional: remove oat/ to get more complete structures
					if cleanOat {
						if pkgName != "" {
							RemoveOatDirsForPackage(pkgName)
						} else if uid != 0 {
							RemoveOatDirsByUID(uid)
						}
					}

					dumper := NewDexDumper(libArtPath, uid, outputDir, trace, autoFix, executeOffset, nterpOffset)

					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()

					sigChan := make(chan os.Signal, 1)
					signal.Notify(sigChan, os.Interrupt, unix.SIGTERM, unix.SIGHUP, unix.SIGQUIT)
					defer signal.Stop(sigChan)

					go func() {
						for {
							select {
							case sig := <-sigChan:
								log.Printf("Received signal %v, flushing JSON and shutting down...", sig)
								cancel()
								return
							case <-ctx.Done():
								return
							}
						}
					}()

					if err := dumper.Start(ctx); err != nil {
						return fmt.Errorf("failed to start dumper: %w", err)
					}
					if err := dumper.Stop(); err != nil {
						log.Printf("Failed to stop dumper cleanly: %v", err)
					}
					log.Println("DexDumper stopped")
					return nil
				},
			},
			{
				Name:        "fix",
				Usage:       "Fix dumped DEX files in a directory",
				Description: "Scan a directory for dumped DEX files and fix headers/structures for readability.",
				CustomHelpTemplate: `NAME:
   {{.HelpName}} - {{.Usage}}

USAGE:
   {{.HelpName}} [command options]

DESCRIPTION:
   {{.Description}}

OPTIONS:
   {{range .VisibleFlags}}{{.}}
   {{end}}`,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "dir", Aliases: []string{"d"}, Usage: "Directory containing dumped DEX files", Required: true},
				},
				Action: func(c *cli.Context) error {
					outDir := c.String("dir")
					if err := FixDexDirectory(outDir); err != nil {
						return fmt.Errorf("fix dex failed: %w", err)
					}
					log.Printf("Fix completed for directory: %s", outDir)
					return nil
				},
			},
			{
				Name:        "dumpso",
				Usage:       "Dump native .so libraries from a running process's memory",
				Description: "Scan /proc/<pid>/maps for loaded shared libraries (plus optionally self-mapped anonymous ELF images), read their full mapped span from process memory, and write raw dumps; provide either --uid or --name to select the target process(es).",
				CustomHelpTemplate: `NAME:
   {{.HelpName}} - {{.Usage}}

USAGE:
   {{.HelpName}} [command options]

DESCRIPTION:
   {{.Description}}

OPTIONS:
   {{range .VisibleFlags}}{{.}}
   {{end}}`,
				Flags: []cli.Flag{
					&cli.Uint64Flag{Name: "uid", Aliases: []string{"u"}, Usage: "Filter by UID (alternative to --name)"},
					&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "Android package name to derive UID (alternative to --uid)"},
					&cli.StringFlag{Name: "lib", Aliases: []string{"l"}, Usage: "Only dump libraries whose path contains this substring (default: all app-mapped .so files)"},
					&cli.StringFlag{Name: "out", Aliases: []string{"o", "output"}, Usage: "Output directory on device", Value: "/data/local/tmp/so_out", DefaultText: "/data/local/tmp/so_out"},
					&cli.BoolFlag{Name: "anon", Aliases: []string{"a"}, Usage: "Also scan anonymous memory regions for self-mapped ELF images", Value: true},
					&cli.BoolFlag{Name: "auto-fix", Aliases: []string{"f"}, Usage: "Automatically fix dumped .so files after dumping", Value: true},
					&cli.BoolFlag{Name: "no-anon", Usage: "Disable anonymous ELF region scanning"},
					&cli.BoolFlag{Name: "no-auto-fix", Usage: "Disable automatic .so fixing"},
					&cli.BoolFlag{Name: "include-system", Usage: "Also dump system libraries under /system, /apex, /vendor (default: skip them)"},
					&cli.BoolFlag{Name: "watch", Aliases: []string{"w"}, Usage: "Keep watching the process and dump modules as they appear (captures runtime-decrypted libs)"},
					&cli.Uint64Flag{Name: "watch-interval", Usage: "Seconds between map re-scans in --watch mode", Value: 1},
					&cli.Uint64Flag{Name: "watch-timeout", Usage: "Stop --watch after N seconds (0 = until interrupted)", Value: 60},
				},
				Action: func(c *cli.Context) error {
					uid := uint32(c.Uint64("uid"))
					pkgName := c.String("name")
					libFilter := c.String("lib")
					outputDir := c.String("out")
					includeAnon := c.Bool("anon") && !c.Bool("no-anon")
					autoFix := c.Bool("auto-fix") && !c.Bool("no-auto-fix")
					includeSystem := c.Bool("include-system")
					watch := c.Bool("watch")
					watchInterval := c.Uint64("watch-interval")
					watchTimeout := c.Uint64("watch-timeout")

					if err := os.MkdirAll(outputDir, 0755); err != nil {
						return fmt.Errorf("failed to create output directory %s: %w", outputDir, err)
					}

					if uid == 0 && pkgName == "" {
						return fmt.Errorf("either --uid or --name must be provided")
					}
					if uid == 0 && pkgName != "" {
						resolved, err := LookupUIDByPackageName(pkgName)
						if err != nil {
							return err
						}
						uid = resolved
						log.Printf("[+] Resolved UID %d from package %q", uid, pkgName)
					}

					var dumped []string
					if watch {
						ctx, cancel := context.WithCancel(context.Background())
						if watchTimeout > 0 {
							ctx, cancel = context.WithTimeout(context.Background(), time.Duration(watchTimeout)*time.Second)
						}
						defer cancel()

						sigChan := make(chan os.Signal, 1)
						signal.Notify(sigChan, os.Interrupt, unix.SIGTERM)
						go func() {
							<-sigChan
							cancel()
						}()

						log.Printf("[+] Watching uid %d every %ds (timeout %ds; Ctrl-C to stop)...", uid, watchInterval, watchTimeout)
						dumped = WatchAndDump(ctx, uid, libFilter, includeAnon, includeSystem, outputDir, time.Duration(watchInterval)*time.Second)
					} else {
						pids, err := FindPidsForUID(uid)
						if err != nil {
							return err
						}
						log.Printf("[+] Found %d process(es) for uid %d: %v", len(pids), uid, pids)

						for _, pid := range pids {
							mods, err := ScanSoModules(pid, libFilter, includeAnon, includeSystem)
							if err != nil {
								log.Printf("[!] scan failed for pid %d: %v", pid, err)
								continue
							}
							log.Printf("[+] pid %d: found %d candidate module(s)", pid, len(mods))
							dumped = append(dumped, DumpSoModules(pid, mods, outputDir)...)
						}
					}

					if autoFix && len(dumped) > 0 {
						log.Printf("[+] Auto-fixing dumped .so files...")
						if err := FixSoDirectory(outputDir, nil); err != nil {
							log.Printf("[!] Auto-fix failed: %v", err)
						}
					}

					log.Printf("[+] Done. Dumped %d .so file(s) to %s", len(dumped), outputDir)
					return nil
				},
			},
			{
				Name:        "fixso",
				Usage:       "Fix dumped .so files in a directory",
				Description: "Scan a directory for dumped .so files and rewrite segment headers for static analysis tools.",
				CustomHelpTemplate: `NAME:
   {{.HelpName}} - {{.Usage}}

USAGE:
   {{.HelpName}} [command options]

DESCRIPTION:
   {{.Description}}

OPTIONS:
   {{range .VisibleFlags}}{{.}}
   {{end}}`,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "dir", Aliases: []string{"d"}, Usage: "Directory containing dumped .so files", Required: true},
					&cli.StringFlag{Name: "symbols", Aliases: []string{"s"}, Usage: "File of 'offset name' lines to inject as .symtab symbols (e.g. recovered JNI functions)"},
				},
				Action: func(c *cli.Context) error {
					outDir := c.String("dir")
					var injected []InjectedSym
					if sf := c.String("symbols"); sf != "" {
						syms, err := parseSymbolFile(sf)
						if err != nil {
							return fmt.Errorf("read symbols file: %w", err)
						}
						injected = syms
						log.Printf("[+] Loaded %d symbol(s) to inject from %s", len(injected), sf)
					}
					if err := FixSoDirectory(outDir, injected); err != nil {
						return fmt.Errorf("fix so failed: %w", err)
					}
					log.Printf("Fix completed for directory: %s", outDir)
					return nil
				},
			},
		},
		Action: func(c *cli.Context) error {
			// Default to "dump" to keep UX simple when not specifying subcommand
			return cli.ShowAppHelp(c)
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
