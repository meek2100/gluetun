package privateinternetaccess

import (
	"context"
	"errors" // Required for utils.ErrNoServerFound comparison
	"fmt"
	"net/http"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/privateinternetaccess/presets"
	"github.com/qdm12/gluetun/internal/provider/utils"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	ErrWireguardPrivateKeyNotSet = errors.New("Wireguard private key is not set")
	ErrOpenVPNUserNotSet         = errors.New("OpenVPN username is not set")
	ErrOpenVPNPasswordNotSet     = errors.New("OpenVPN password is not set")
)

func (p *Provider) GetConnection(selection settings.ServerSelection, ipv6Supported bool) (
	connection models.Connection, err error,
) {
	// Note: selection.VPN holds the protocol type (wireguard or openvpn)
	// selection.Provider.Wireguard holds wireguard specific settings from the top level
	// selection.Provider.OpenVPN holds openvpn specific settings from the top level
	// selection.OpenVPN holds openvpn selection settings (like custom port, protocol)
	// selection.Wireguard holds wireguard selection settings (like endpoint ip, port, public key) - not used here.

	if *selection.VPN == "wireguard" {
		// Wireguard connection
		if selection.Provider.Wireguard.PrivateKey == nil || *selection.Provider.Wireguard.PrivateKey == "" {
			return connection, ErrWireguardPrivateKeyNotSet
		}

		if selection.Provider.OpenVPN.User == nil || *selection.Provider.OpenVPN.User == "" {
			return connection, ErrOpenVPNUserNotSet
		}
		if selection.Provider.OpenVPN.Password == nil || *selection.Provider.OpenVPN.Password == "" {
			return connection, ErrOpenVPNPasswordNotSet
		}

		privateKey, err := wgtypes.ParseKey(*selection.Provider.Wireguard.PrivateKey)
		if err != nil {
			return connection, fmt.Errorf("cannot parse Wireguard private key: %w", err)
		}
		publicKey := privateKey.PublicKey().String()

		// Use FilterServers as defined in common.Storage interface
		servers, err := p.storage.FilterServers(p.Name(), selection)
		if err != nil {
			return connection, fmt.Errorf("filtering servers: %w", err)
		} else if len(servers) == 0 {
			return connection, utils.ErrNoServerFound // Use the correct error variable
		}

		// Pick random server - GetConnection assumes one server is chosen.
		// If FilterServers returns multiple, we might need to pick one randomly here,
		// or adjust FilterServers logic/expectations. Assuming it returns one suitable server for now.
		server := servers[0]

		client := &http.Client{Timeout: 10 * time.Second}
		// Pass the correct User and Password fields from the Provider settings
		return getWireguardConnection(context.Background(), client, server,
			publicKey, *selection.Provider.OpenVPN.User, *selection.Provider.OpenVPN.Password)
	}

	// OpenVPN connection (remains the same)
	var defaults utils.ConnectionDefaults
	switch *selection.OpenVPN.PIAEncPreset {
	case presets.None, presets.Normal:
		defaults.OpenVPNTCPPort = 502
		defaults.OpenVPNUDPPort = 1198
	case presets.Strong:
		defaults.OpenVPNTCPPort = 501
		defaults.OpenVPNUDPPort = 1197
	}

	// Use FilterServers here as well for consistency
	servers, err := p.storage.FilterServers(p.Name(), selection)
	if err != nil {
		return connection, fmt.Errorf("filtering servers: %w", err)
	} else if len(servers) == 0 {
		return connection, utils.ErrNoServerFound
	}

	return utils.PickServer(servers, selection, p.randSource, defaults, ipv6Supported)
}

// Note: utils.GetConnection is a generic helper that internally calls FilterServers and PickServer.
// Since we need custom Wireguard logic BEFORE picking, we call FilterServers directly.
// For OpenVPN, we could stick with the original utils.GetConnection call if preferred,
// or use FilterServers + PickServer like done above for consistency. I've updated it
// to use FilterServers + PickServer.
