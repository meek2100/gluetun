package privateinternetaccess

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/privateinternetaccess/presets"
	"github.com/qdm12/gluetun/internal/provider/utils"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (p *Provider) GetConnection(selection settings.ServerSelection, ipv6Supported bool) (
	connection models.Connection, err error,
) {
	if *selection.VPN == "wireguard" {
		// Wireguard connection
		if *selection.Wireguard.PrivateKey == "" {
			return connection, fmt.Errorf("Wireguard private key is not set")
		}

		privateKey, err := wgtypes.ParseKey(*selection.Wireguard.PrivateKey)
		if err != nil {
			return connection, fmt.Errorf("cannot parse Wireguard private key: %w", err)
		}
		publicKey := privateKey.PublicKey().String()

		servers, err := p.storage.GetServers(p.Name(), selection)
		if err != nil {
			return connection, err
		}

		var server models.Server
		if len(servers) > 0 {
			server = servers[0]
		} else {
			return connection, utils.ErrNoServerFound
		}

		client := &http.Client{Timeout: 10 * time.Second}
		return getWireguardConnection(context.Background(), client, server,
			publicKey, *selection.OpenVPN.User, *selection.OpenVPN.Password)
	}

	// OpenVPN connection
	var defaults utils.ConnectionDefaults
	switch *selection.OpenVPN.PIAEncPreset {
	case presets.None, presets.Normal:
		defaults.OpenVPNTCPPort = 502
		defaults.OpenVPNUDPPort = 1198
	case presets.Strong:
		defaults.OpenVPNTCPPort = 501
		defaults.OpenVPNUDPPort = 1197
	}

	return utils.GetConnection(p.Name(),
		p.storage, selection, defaults, ipv6Supported, p.randSource)
}
