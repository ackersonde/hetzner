package hetznercloud

import (
	"context"
	"fmt"
	"os"

	"github.com/hetznercloud/hcloud-go/hcloud"
)

// bender slackbot methods
func ListAllServers() []*hcloud.Server {
	client := hcloud.NewClient(hcloud.WithToken(os.Getenv("CTX_HETZNER_API_TOKEN")))
	servers, _ := client.Server.All(context.Background())
	return servers
}

func DeleteServer(serverID int) string {
	result := fmt.Sprintf("Successfully deleted server %d: ", serverID)

	client := hcloud.NewClient(hcloud.WithToken(os.Getenv("CTX_HETZNER_API_TOKEN")))
	server, _, err := client.Server.GetByID(context.Background(), serverID)
	if err != nil {
		return fmt.Sprintf("Server %d doesn't exist!\n", serverID)
	}

	_, err = client.Server.Delete(context.Background(), server)
	if err != nil {
		return fmt.Sprintf("Unable to delete server [%d] %s: %s\n", serverID, server.Name, err.Error())
	}

	return result + server.Name
}
