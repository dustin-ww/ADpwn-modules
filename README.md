# ADPwn Module Library

## Enumeration Modules

- Network Exploration (v0.1)
- DNS Exploration (v0.1)

## Attack Modules

- Printer Nightmare (v0.1)
- NTLM Coercing (v0.1)
- DACL Abuse (v0.1)

# Develop your own modules

Use this template to implement your own plugins: 


    package <module_package>
    
    import (
    "ADPwn-core/pkg/model/adpwn/input"
    "ADPwn-core/pkg/model/adpwnsdk"
    plugin "ADPwn-core/pkg/module_exec"
    "ADPwn-core/pkg/sse"
    )
    
    // Register plugin in adpwn module registry
    func init() {
    module := &<module_name>{
    configKey: "<module_name>",
    }
    plugin.RegisterPlugin(module)
    
    }
    
    
    type DNSExplorer struct {
    // Internal
    configKey string
    // Services
    services *adpwnsdk.Services
    // UI Logger
    logger *sse.SSELogger
    }
    
    func (n *<module_name>) ConfigKey() string {
    return n.configKey
    }
    
    func (n *<module_name>) SetServices(services *adpwnsdk.Services) {
    n.services = services
    }
    
    // THIS METHOD IS CALLED BY THE ADpwn CORE
    func (n *<module_name>) ExecuteModule(params *input.Parameter, logger *sse.SSELogger) error {
    // INSERT MAIN LOGIC HERE
    return nil
    }
    
