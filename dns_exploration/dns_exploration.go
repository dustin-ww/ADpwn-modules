package dns_exploration

import (
	"ADPwn-core/pkg/model/adpwn/input"
	"ADPwn-core/pkg/model/adpwnsdk"
	plugin "ADPwn-core/pkg/module_exec"
	"ADPwn-core/pkg/sse"
)

type DNSExplorer struct {
	Dependencies []string
	Modes        []string
	configKey    string
}

func (n *DNSExplorer) ConfigKey() string {
	//TODO implement me
	panic("implement me")
}

func (n *DNSExplorer) SetServices(services *adpwnsdk.Services) {
	//TODO implement me
	panic("implement me")
}

func (n *DNSExplorer) DependsOn() int {
	//TODO implement me
	panic("implement me")
}

func (n *DNSExplorer) GetDependencies() []string {
	return n.Dependencies
}

func (n *DNSExplorer) ExecuteModule(params *input.Parameter, logger *sse.SSELogger) error {
	return nil
}

// INIT
func init() {
	module := &DNSExplorer{
		configKey: "DNSExplorer",
	}
	plugin.RegisterPlugin(module)

}
