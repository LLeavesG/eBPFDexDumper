//go:build arm64

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"

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
		Usage: "Dump in-memory DEX and method bytecode or fix dumped DEX files",
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
