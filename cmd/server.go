package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/narukoshin/yako/v1/server"
)

// dataDir, port, host are CLI flags for the server start command.
var (
	dataDir string
	port    int
	host    string
)

// init registers the server command and the start subcommand with its flags.
func init() {
	rootCmd.AddCommand(serverCmd)
	serverCmd.AddCommand(serverStartCmd)
	serverStartCmd.Flags().StringVarP(&dataDir, "data-dir", "d", "", "path to server data directory")
	serverStartCmd.Flags().IntVarP(&port, "port", "p", 0, "server listening port")
	serverStartCmd.Flags().StringVarP(&host, "host", "H", "127.0.0.1", "server listening host")
}

// serverCmd is the parent command for server subcommands.
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run the yako sync server",
}

// serverStartCmd starts the HTTP sync server with optional env-based admin creation.
var serverStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the HTTP sync server",
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runServerStart(cmd)
	},
}

// runServerStart loads config, creates admin if needed, and starts the HTTP server.
func runServerStart(cmd *cobra.Command) error {
	// Load or initialize server config
	dir := dataDir
	if dir == "" {
		dir = os.Getenv("YAKO_DATA_DIR")
	}
	cfg, err := server.LoadOrInitConfig(dir)
	if err != nil {
		return fmt.Errorf("server config: %w", err)
	}

	if port != 0 {
		cfg.Port = port
	} else if envPort := os.Getenv("YAKO_PORT"); envPort != "" {
		p, err := strconv.Atoi(envPort)
		if err != nil {
			return fmt.Errorf("invalid YAKO_PORT: %w", err)
		}
		cfg.Port = p
	}

	if cmd.Flags().Lookup("host").Changed {
		cfg.Host = host
	} else if envHost := os.Getenv("YAKO_HOST"); envHost != "" {
		cfg.Host = envHost
	} else {
		cfg.Host = "127.0.0.1"
	}

	// Create server instance
	srv := server.New(cfg)

	// Check if admin user exists; if not, create one
	needsAdmin, err := srv.NeedsAdmin()
	if err != nil {
		return fmt.Errorf("check users: %w", err)
	}
	if needsAdmin {
		// Allow setting admin credentials via environment variables for non-interactive use (e.g. Docker)
		adminUser := os.Getenv("YAKO_ADMIN_USERNAME")
		adminPass := os.Getenv("YAKO_ADMIN_PASSWORD")
		if adminUser != "" && adminPass != "" {
			if err := srv.CreateAdmin(adminUser, adminPass); err != nil {
				return fmt.Errorf("create admin from env: %w", err)
			}
			fmt.Printf("Admin user '%s' created from environment\n", adminUser)
		} else {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return fmt.Errorf("stdin is not a terminal; set YAKO_ADMIN_USERNAME and YAKO_ADMIN_PASSWORD to create admin non-interactively")
			}
			fmt.Println("No admin user found. Create one now.")
			adminUser, err = readLine("Admin username: ")
			if err != nil {
				return err
			}
			if adminUser == "" {
				return fmt.Errorf("admin username required")
			}
			adminPass, err = readPassphrase("Admin password: ")
			if err != nil {
				return err
			}
			if adminPass == "" {
				return fmt.Errorf("admin password required")
			}
			if err := srv.CreateAdmin(adminUser, adminPass); err != nil {
				return fmt.Errorf("create admin: %w", err)
			}
			fmt.Printf("Admin user '%s' created\n", adminUser)
		}
	}

	fmt.Printf("yako server listening on %s\n", cfg.ListenAddr())
	return srv.Start()
}
