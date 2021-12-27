package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/hetznercloud/hcloud-go/hcloud"
	"golang.org/x/crypto/ssh"
)

var sshPrivateKeyFilePath = "/home/runner/.ssh/id_rsa"
var envFile = "/tmp/new_hetzner_server_params"

func main() {
	client := hcloud.NewClient(hcloud.WithToken(os.Getenv("CTX_HETZNER_API_TOKEN")))

	fnPtr := flag.String("fn", "createServer|cleanupDeploy|firewallSSH|createSnapshot|checkServer", "which function to run")
	ipPtr := flag.String("ip", "<internet ip addr of github action instance>", "see prev param")
	tagPtr := flag.String("tag", "traefik", "label with which to associate this resource")
	serverPtr := flag.Int("serverID", 0, "server ID to check")
	flag.Parse()

	if *fnPtr == "createServer" {
		createServer(client, *tagPtr)
	} else if *fnPtr == "cleanupDeploy" {
		cleanupDeploy(client, *tagPtr)
	} else if *fnPtr == "firewallSSH" {
		allowSSHipAddress(client, *ipPtr, *tagPtr, *serverPtr)
	} else if *fnPtr == "checkServer" {
		checkServer(client, *serverPtr)
	}

	/* For checking out new server & image types:
	types, _ := client.ServerType.All(context.Background())
	for _, typee := range types {
		fmt.Printf("type[%d] %s x %d cores (%f RAM)\n", typee.ID,
			typee.Description, typee.Cores, typee.Memory)
	}

	images, _ := client.Image.All(context.Background())
	for _, image := range images {
		fmt.Printf("image[%d] %s\n", image.ID, image.Name)
	}

	existingServer := getExistingServer(client)
	fmt.Printf("%d : %s\n", existingServer.ID, existingServer.PublicNet.IPv6.IP)
	*/
}

func allowSSHipAddress(client *hcloud.Client, ipAddr string, tag string, serverID int) {
	ctx := context.Background()

	opts := hcloud.FirewallCreateOpts{
		Name:   "githubBuildDeploy-" + os.Getenv("GITHUB_RUN_ID"),
		Labels: map[string]string{"access": "github"},
		Rules: []hcloud.FirewallRule{{
			Direction: hcloud.FirewallRuleDirectionIn,
			SourceIPs: []net.IPNet{{
				IP:   net.ParseIP(ipAddr),
				Mask: net.CIDRMask(32, 32),
			}},
			Protocol: "tcp",
			Port:     String("22"),
		}},
		ApplyTo: []hcloud.FirewallResource{{
			Type: hcloud.FirewallResourceTypeLabelSelector,
			LabelSelector: &hcloud.FirewallResourceLabelSelector{
				Selector: "label=" + tag},
		}},
	}
	client.Firewall.Create(ctx, opts)

	checkServer(client, serverID)
}

func checkServer(client *hcloud.Client, serverID int) {
	ctx := context.Background()
	if serverID != 0 {
		server, _, _ := client.Server.GetByID(ctx, serverID)
		if server.Status != hcloud.ServerStatusRunning {
			client.Server.Poweron(ctx, server)
		}
	}
}

func listVolume(client *hcloud.Client) {
	volumeID, _ := strconv.Atoi(os.Getenv("CTX_HETZNER_VAULT_VOLUME_ID"))
	volume, _, err := client.Volume.GetByID(context.Background(), volumeID)
	if err != nil {
		log.Fatalf("error retrieving volume: %s\n", err)
	}
	if volume != nil {
		fmt.Printf("volume %d: %q\n", volumeID, volume.LinuxDevice)
	} else {
		fmt.Printf("volume %d not found\n", volumeID)
	}
}

func createServer(client *hcloud.Client, tag string) {
	ctx := context.Background()

	// find existing server
	existingServer := getExistingServer(client, tag)

	// detach existing volume
	volumeID, _ := strconv.Atoi(os.Getenv("CTX_HETZNER_VAULT_VOLUME_ID"))
	volume, _, _ := client.Volume.GetByID(ctx, volumeID)
	action, _, err := client.Volume.Detach(ctx, volume)
	waitForAction(client, action, err)

	// prepare new server
	myKey, _, _ := client.SSHKey.GetByName(ctx, "ackersond")
	deploymentKey := createSSHKey(client, os.Getenv("GITHUB_RUN_ID"))

	ubuntuUserData, _ := ioutil.ReadFile("ubuntu_userdata.sh")

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	result, _, err := client.Server.Create(ctx, hcloud.ServerCreateOpts{
		Name:       "h" + os.Getenv("GITHUB_RUN_ID") + "-" + timestamp + ".ackerson.de",
		ServerType: &hcloud.ServerType{ID: 22},  // AMD 2 core, 2GB Ram
		Image:      &hcloud.Image{ID: 15512617}, // ubuntu-20.04
		Location:   &hcloud.Location{Name: "nbg1"},
		Labels:     map[string]string{"label": tag},
		Volumes:    []*hcloud.Volume{{ID: volumeID}},
		Automount:  Bool(false),
		UserData:   string(ubuntuUserData),
		SSHKeys:    []*hcloud.SSHKey{deploymentKey, myKey},
	})
	if err != nil {
		log.Fatalf("*** unable to create server: %s\n", err)
	}
	if result.Server == nil {
		log.Fatalf("*** no server created?\n")
	} else {
		existingServerVars := ""
		if existingServer.Name != "" {
			existingServerVars = "\nexport OLD_SERVER_IPV6=" +
				existingServer.PublicNet.IPv6.IP.String()

			// update existingServer Label with "delete":"true" !
			client.Server.Update(ctx, existingServer, hcloud.ServerUpdateOpts{
				Labels: map[string]string{"delete": "true"},
			})
		}

		// Write key metadata from existing/new servers
		envVarsFile := []byte(
			"export NEW_SERVER_IPV4=" + result.Server.PublicNet.IPv4.IP.String() +
				"\nexport NEW_SERVER_IPV6=" + result.Server.PublicNet.IPv6.IP.String() +
				"\nexport NEW_SERVER_ID=" + strconv.Itoa(result.Server.ID) +
				existingServerVars)

		err = ioutil.WriteFile(envFile, envVarsFile, 0644)
		if err != nil {
			log.Fatalf("Failed to write %s: %s\n", envFile, err)
		} else {
			log.Printf("wrote %s\n", envFile)
		}
	}
}

func waitForAction(client *hcloud.Client, action *hcloud.Action, err error) {
	if err == nil && action.Status != "success" {
		for {
			action, _, _ := client.Action.GetByID(context.Background(), action.ID)
			if action.Status == hcloud.ActionStatusSuccess {
				break
			} else if action.Status == hcloud.ActionStatusRunning {
				log.Printf("action %s ... sleeping 3secs\n", action.Status)
				time.Sleep(3 * time.Second)
			} else {
				log.Printf("action failed %s\n", action.ErrorMessage)
			}
		}
	} else if err != nil {
		log.Printf("Unable to perform action: %s\n", err)
	}
}

func cleanupDeploy(client *hcloud.Client, tag string) {
	ctx := context.Background()
	opts := hcloud.ServerListOpts{ListOpts: hcloud.ListOpts{LabelSelector: "delete=true"}}
	servers, _ := client.Server.AllWithOpts(ctx, opts)
	for _, server := range servers {
		_, err := client.Server.Delete(ctx, server)
		if err == nil {
			log.Printf("DELETED Server %s\n", server.Name)
		} else {
			log.Fatalf("Unable to delete server %s (%s)!!!\n", server.Name, err)
		}
	}

	deployKeys, _ := client.SSHKey.AllWithOpts(ctx, hcloud.SSHKeyListOpts{
		ListOpts: hcloud.ListOpts{LabelSelector: "access=github"},
	})
	for _, deployKey := range deployKeys {
		_, err := client.SSHKey.Delete(ctx, deployKey)
		if err == nil {
			log.Printf("DELETED SSH key %s\n", deployKey.Name)
		} else {
			log.Fatalf("Unable to delete SSH key %s (%s) !!!\n", deployKey.Name, err)
		}
	}

	firewalls, _ := client.Firewall.AllWithOpts(ctx, hcloud.FirewallListOpts{
		ListOpts: hcloud.ListOpts{LabelSelector: "access=github"},
	})
	resources := []hcloud.FirewallResource{
		{
			Type: hcloud.FirewallResourceTypeLabelSelector,
			LabelSelector: &hcloud.FirewallResourceLabelSelector{
				Selector: "label=" + tag},
		},
	}
	for _, firewall := range firewalls {
		actions, _, err := client.Firewall.RemoveResources(ctx, firewall, resources)
		if len(actions) > 0 {
			waitForAction(client, actions[0], err)
		}
		_, err = client.Firewall.Delete(ctx, firewall)
		if err == nil {
			log.Printf("DELETED firewall %s\n", firewall.Name)
		} else {
			log.Printf("DOUBLE REMOVE RESOURCES?!")
			actions, _, err := client.Firewall.RemoveResources(ctx, firewall, resources)
			if len(actions) > 0 {
				waitForAction(client, actions[0], err)
			}
			_, err = client.Firewall.Delete(ctx, firewall)
			if err != nil {
				log.Printf("Unable to delete FW %s (%s) !!!\n", firewall.Name, err)
			}
		}
	}
}

func getExistingServer(client *hcloud.Client, tag string) *hcloud.Server {
	ctx := context.Background()
	opts := hcloud.ServerListOpts{ListOpts: hcloud.ListOpts{LabelSelector: "label=" + tag}}
	existingServers, _ := client.Server.AllWithOpts(ctx, opts)
	server := new(hcloud.Server)
	if len(existingServers) == 1 {
		server = existingServers[0]
	}

	return server
}

func Bool(b bool) *bool { return &b }

func String(s string) *string { return &s }

func createSSHKey(client *hcloud.Client, githubBuild string) *hcloud.SSHKey {
	privateKeyPair, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Printf("rsa.GenerateKey returned error: %v", err)
	}

	publicRsaKey, err := ssh.NewPublicKey(privateKeyPair.Public())
	if err != nil {
		log.Printf("ssh.NewPublicKey returned error: %v", err)
	}
	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)

	createRequest := hcloud.SSHKeyCreateOpts{
		Name:      githubBuild + "SSHkey",
		PublicKey: string(pubKeyBytes),
		Labels:    map[string]string{"access": "github"},
	}

	key, _, err := client.SSHKey.Create(context.Background(), createRequest)
	if err != nil {
		log.Printf("Keys.Create returned error: %v", err)
	} else {
		pemdata := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(privateKeyPair),
			},
		)
		err := ioutil.WriteFile(sshPrivateKeyFilePath, pemdata, 0400)
		if err != nil {
			fmt.Printf("Failed to write %s: %s", sshPrivateKeyFilePath, err.Error())
		}
	}

	return key
}
