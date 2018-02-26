package cmd

import (
	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"

	daemon "github.com/openshift/image-build-daemon"
)

// New provides a command that runs a Docker build daemon proxy.
func New(name string) *cobra.Command {
	server := &daemon.Server{
		Mode: "passthrough",
	}
	cmd := &cobra.Command{
		Use:   name,
		Short: "Start a build proxy",
		Long: heredoc.Doc(`
			Start a Docker build proxy

			This command launches a proxy that handles the Docker build API and enforces authorization 
			checks from the client.`),
		RunE: func(c *cobra.Command, args []string) error {
			return server.Start()
		},
	}
	cmd.Flags().StringVar(&server.Mode, "mode", server.Mode, "The backend build implementation to use. Accepts 'imagebuilder' or 'passthrough'.")
	cmd.Flags().StringVar(&server.BindDirectory, "bind-local", server.BindDirectory, "When set the listener socket will be bound into this directory for any created pod instead of the pod's directory.")
	return cmd
}
