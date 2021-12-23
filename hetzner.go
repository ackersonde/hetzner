package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"

	"github.com/hetznercloud/hcloud-go/hcloud"
	"golang.org/x/crypto/ssh"
)

var sshPrivateKeyFilePath = "/home/runner/.ssh/id_rsa"
var envFile = "/tmp/new_digital_ocean_droplet_params"
var traefikLabelSel = "project=traefik"

func main() {
	client := hcloud.NewClient(hcloud.WithToken(os.Getenv("CTX_HETZNER_API_TOKEN")))

	listVolume(client)

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

	existingServer := getExistingTraefikServer(client)
	fmt.Printf("%d : %s\n", existingServer.ID, existingServer.PublicNet.IPv6.IP)
	*/

	createServer(client)
	deleteServersAndDeployKeys(client)
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

func createServer(client *hcloud.Client) {
	ctx := context.Background()

	// find existing server
	existingServer := getExistingTraefikServer(client)

	// prepare new server
	myKey, _, _ := client.SSHKey.GetByName(ctx, "ackersond")
	deploymentKey := createSSHKey(client, os.Getenv("GITHUB_RUN_ID"))

	volumeID, _ := strconv.Atoi(os.Getenv("CTX_HETZNER_VAULT_VOLUME_ID"))
	ubuntuUserData, _ := ioutil.ReadFile("ubuntu_userdata.sh")

	result, _, err := client.Server.Create(ctx, hcloud.ServerCreateOpts{
		Name:       "h" + os.Getenv("GITHUB_RUN_ID") + ".ackerson.de",
		ServerType: &hcloud.ServerType{ID: 22},  // AMD 2 core, 2GB Ram
		Image:      &hcloud.Image{ID: 15512617}, // ubuntu-20.04
		Location:   &hcloud.Location{Name: "nbg1"},
		Labels:     map[string]string{"project": "traefik"},
		Volumes:    []*hcloud.Volume{{ID: volumeID}},
		Automount:  Bool(false),
		UserData:   string(ubuntuUserData),
		SSHKeys:    []*hcloud.SSHKey{deploymentKey, myKey},
	})
	if err != nil {
		log.Fatal(err)
	}
	if result.Server == nil {
		log.Fatal("no server")
	}

	// Write key metadata from existing/new servers
	envVarsFile := []byte(
		"export NEW_SERVER_IPV4=" + string(result.Server.PublicNet.IPv4.IP) +
			"\nexport NEW_SERVER_IPV6=" + string(result.Server.PublicNet.IPv6.IP) +
			"\nexport DEPLOY_KEY_ID=" + strconv.Itoa(deploymentKey.ID) +
			"\nexport NEW_SERVER_ID=" + strconv.Itoa(result.Server.ID) +
			"\nexport OLD_SERVER_ID=" + strconv.Itoa(existingServer.ID) +
			"\nexport OLD_SERVER_IPV6=" + string(existingServer.PublicNet.IPv6.IP))

	err = ioutil.WriteFile(envFile, envVarsFile, 0644)
	if err != nil {
		fmt.Printf("Failed to write %s: %s", envFile, err)
	}

	// update existingServer Label with "delete":"true" !
	client.Server.Update(ctx, existingServer, hcloud.ServerUpdateOpts{
		Labels: map[string]string{"delete": "true"},
	})
}

func deleteServersAndDeployKeys(client *hcloud.Client) {
	ctx := context.Background()
	opts := hcloud.ServerListOpts{ListOpts: hcloud.ListOpts{LabelSelector: "delete=true"}}
	servers, _ := client.Server.AllWithOpts(ctx, opts)
	for _, server := range servers {
		_, err := client.Server.Delete(ctx, server)
		if err == nil {
			log.Printf("DELETED %s\n", server.Name)
		} else {
			log.Fatalf("Unable to delete %s !!!\n", server.Name)
		}
	}

	deployKeys, _ := client.SSHKey.AllWithOpts(ctx, hcloud.SSHKeyListOpts{
		ListOpts: hcloud.ListOpts{LabelSelector: traefikLabelSel},
	})
	for _, deployKey := range deployKeys {
		client.SSHKey.Delete(ctx, deployKey)
	}
}

func getExistingTraefikServer(client *hcloud.Client) *hcloud.Server {
	opts := hcloud.ServerListOpts{ListOpts: hcloud.ListOpts{LabelSelector: traefikLabelSel}}
	existingServers, _ := client.Server.AllWithOpts(context.Background(), opts)
	server := new(hcloud.Server)
	if len(existingServers) == 1 {
		server = existingServers[0]
	}

	return server
}

func Bool(b bool) *bool { return &b }

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
		Labels:    map[string]string{"project": "traefik"},
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
