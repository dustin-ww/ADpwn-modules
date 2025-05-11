package dns_exploration

import (
	"ADPwn-core/pkg/model/adpwn/input"
	"ADPwn-core/pkg/model/adpwnsdk"
	plugin "ADPwn-core/pkg/module_exec"
	"ADPwn-core/pkg/sse"
)

// INIT
func init() {
	module := &DNSExplorer{
		configKey: "DNSExplorer",
	}
	plugin.RegisterPlugin(module)

}

type DNSExplorer struct {
	// Internal
	configKey string
	// Services
	services *adpwnsdk.Services
	// Tool Adaptera
	logger *sse.SSELogger
}

func (n *DNSExplorer) ConfigKey() string {
	return n.configKey
}

func (n *DNSExplorer) SetServices(services *adpwnsdk.Services) {
	n.services = services
}

// THIS METHOD IS CALLED BY THE ADpwn CORE
func (n *DNSExplorer) ExecuteModule(params *input.Parameter, logger *sse.SSELogger) error {
	// INSERT MAIN LOGIC HERE
	return nil
}
