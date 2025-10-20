package privateinternetaccess

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/qdm12/gluetun/internal/models"
)

func getWireguardConnection(ctx context.Context, client *http.Client,
	server models.Server, publicKey, username, password string) (connection models.Connection, err error) {
	token, err := FetchToken(ctx, client, username, password)
	if err != nil {
		return connection, fmt.Errorf("failed to get token: %w", err)
	}

	params := url.Values{}
	params.Add("pt", token)
	params.Add("pubkey", publicKey)

	url := url.URL{
		Scheme:   "https",
		Host:     fmt.Sprintf("%s:1337", server.Hostname),
		Path:     "/addKey",
		RawQuery: params.Encode(),
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
	if err != nil {
		return connection, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return connection, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return connection, fmt.Errorf("failed to get wireguard connection: status code %d", resp.StatusCode)
	}

	var data struct {
		ServerKey  string   `json:"server_key"`
		ServerPort int      `json:"server_port"`
		PeerIP     string   `json:"peer_ip"`
		DNSServers []string `json:"dns_servers"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return connection, err
	}

	return models.Connection{
		IP:        server.IPs[0],
		Port:      uint16(data.ServerPort),
		PubKey:    data.ServerKey,
		WGAddress: data.PeerIP,
	}, nil
}
