package printer_nightmare

import (
	"ADPwn-core/pkg/model/adpwn/input"
	"ADPwn-core/pkg/model/adpwnsdk"
	plugin "ADPwn-core/pkg/module_exec"
	"ADPwn-core/pkg/sse"
)

type PrinterNightmare struct {
	configKey string
}

func (n *PrinterNightmare) ConfigKey() string {
	//TODO implement me
	panic("implement me")
}

func (n *PrinterNightmare) SetServices(services *adpwnsdk.Services) {
	//TODO implement me
	panic("implement me")
}

func (n *PrinterNightmare) DependsOn() int {
	//TODO implement me
	panic("implement me")
}

func (n *PrinterNightmare) ExecuteModule(params *input.Parameter, logger *sse.SSELogger) error {
	return nil
}

// INIT
func init() {
	module := &PrinterNightmare{
		configKey: "PrinterNightmare",
	}
	plugin.RegisterPlugin(module)
}
