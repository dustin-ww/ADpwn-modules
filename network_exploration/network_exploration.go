package network_exploration

import (
	"ADPwn-core/pkg/adapter"
	"ADPwn-core/pkg/adapter/scan"
	"ADPwn-core/pkg/adapter/serializable"
	"ADPwn-core/pkg/interfaces"
	"ADPwn-core/pkg/model"
	"ADPwn-core/pkg/model/adpwn/input"
	"ADPwn-core/pkg/model/adpwnsdk"
	plugin "ADPwn-core/pkg/module_exec"
	"ADPwn-core/pkg/sse"
	"ADpwn-modules/network_exploration/internal"
	"context"
	"fmt"
	"github.com/antchfx/xmlquery"
	"log"
	"regexp"
	"strings"
	"time"
)

// INITIALIZE MODULE AS ADPWN PLUGIN
func init() {
	module := &NetworkExplorer{
		configKey: "NetworkExplorer",
	}
	plugin.RegisterPlugin(module)
}

type NetworkExplorer struct {
	// Internal
	configKey string
	// Services
	services *adpwnsdk.Services
	// Tool Adaptera
	logger *sse.SSELogger
}

func (n *NetworkExplorer) SetServices(services *adpwnsdk.Services) {
	n.services = services
}

func (n *NetworkExplorer) ConfigKey() string {
	return n.configKey
}

// ExecuteModule method called by module loader
func (n *NetworkExplorer) ExecuteModule(params *input.Parameter, logger *sse.SSELogger) error {
	n.logger = logger

	// Log start of module execution
	log.Printf("Executing module key: %s", n.ConfigKey)
	logger.Info(fmt.Sprintf("Starting module: %s", n.ConfigKey))

	logger.Event("scan_start", map[string]interface{}{
		"target_network": params.Inputs["network"],
		"ports":          "1-1024",
	})

	factory := adapter.GetAdapterFactory()
	scanTool := "nmap"
	scanAdapter, err := factory.GetScanAdapter(scanTool)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to get scan adapter: %v", err))
		return err
	}

	scanCtx, scanCancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer scanCancel()

	targetNetwork := "127.0.0.1"
	log.Println("Using Target for network enumeration: " + targetNetwork)

	scanResult, err := scanAdapter.Scan(
		scanCtx,
		scan.WithTargets([]string{targetNetwork}),
		scan.WithPortRange("1-1024"),
		scan.WithServiceScan(),
		scan.WithScriptScan(),
		interfaces.WithTimeout(30*time.Minute),
	)

	if nmapResult, ok := scanResult.(*scan.NmapScanResult); ok {
		// entrypoint to evaluate scan results
		n.processScanResults(*nmapResult, params)
	} else {
		return fmt.Errorf("could not map scan result to nmap result: %v", scanResult)
	}

	// Log completion of module
	logger.Event("module_complete", map[string]interface{}{
		"moduleKey": n.ConfigKey,
		"timestamp": time.Now().Unix(),
	})

	return nil
}

func (n *NetworkExplorer) processScanResults(nmapResult scan.NmapScanResult, params *input.Parameter) {
	// Iterate through each host from nmap output XML
	// Structure: Build domain -> Build host -> Build services
	for _, host := range nmapResult.GetNmapResult().Host {

		var domainUID string
		var hostUID string

		// try to build/get domain from host
		domainUID, err := n.tryToBuildDomain(nmapResult, host.Address[0].Addr, params)
		if err != nil {
			n.logger.Error("failed to build domain", "ip", host.Address[0].Addr, "error", err)
		}

		// BUILD HOST
		hostUID, err = n.buildHost(nmapResult, host.Address[0].Addr, params, domainUID)
		if err != nil {
			n.logger.Error("failed to build host", "ip", host.Address[0].Addr, "error", err)
		}

		// BUILD SERVICES
		n.buildServices(host, hostUID)

	}
}

func (n *NetworkExplorer) buildHost(nmapResult scan.NmapScanResult, ip string, params *input.Parameter, domainUID string) (string, error) {
	if ip == "" {
		return "", fmt.Errorf("IP cannot be empty")
	}

	if params == nil {
		return "", fmt.Errorf("parameters cannot be nil")
	}

	document, err := nmapResult.GetXMLDocument()
	if err != nil {
		n.logger.Error("failed to parse nmap XML document", "ip", ip, "error", err)
		return "", err
	}

	xpathBuilder := internal.NewXPathBuilder(ip)
	hostBuilder := model.NewHostBuilder()
	hostBuilder.WithIP(ip)

	// Extract hostname
	xpath := xpathBuilder.Hostname()
	if node := xmlquery.FindOne(document, xpath); node != nil {
		hostBuilder.WithName(node.InnerText())
	}

	host, err := hostBuilder.Build()
	if err != nil {
		return "", fmt.Errorf("failed to build host: %v", err)
	}

	ctx := context.Background()

	// Create the host in the appropriate domain
	var hostUID string
	if domainUID != "" {
		hostUID, err = n.services.DomainService.AddHost(ctx, domainUID, host)
		if err != nil {
			return "", fmt.Errorf("failed to add host to domain: %v", err)
		}
	} else {
		hostUID, err = n.services.HostService.CreateWithUnknownDomain(ctx, host, params.ProjectUID)
		if err != nil {
			return "", fmt.Errorf("failed to create host: %v", err)
		}
	}

	return hostUID, nil
}

func (n *NetworkExplorer) tryToBuildDomain(nmapResult scan.NmapScanResult, ip string, params *input.Parameter) (string, error) {
	if ip == "" {
		return "", fmt.Errorf("IP cannot be empty")
	}

	if params == nil {
		return "", fmt.Errorf("parameters cannot be nil")
	}

	document, err := nmapResult.GetXMLDocument()
	if err != nil {
		return "", fmt.Errorf("failed to parse nmap XML document: %v", err)
	}

	xpathBuilder := internal.NewXPathBuilder(ip)

	ports := []string{"389", "636", "3268", "3269"}

	strategies := []struct {
		name     string
		getXPath func(port string) string
		extract  func(string) string
	}{
		{
			name:     "LDAP Info",
			getXPath: xpathBuilder.LDAPExtraInfo,
			extract:  extractDomainFromExtrainfo,
		},
		{
			name:     "Certificate Common Name",
			getXPath: xpathBuilder.SSLCertCommonName,
			extract:  extractDomainFromFQDN,
		},
		{
			name:     "SAN-DNS",
			getXPath: xpathBuilder.SSLCertSANDNS,
			extract: func(text string) string {
				return extractDomainFromFQDN(strings.TrimPrefix(text, "DNS:"))
			},
		},
		{
			name:     "issuer domainComponent",
			getXPath: xpathBuilder.SSLCertDomainComponent,
			extract: func(text string) string {
				return text + ".local"
			},
		},
	}

	var domain string
	var usedStrategy string

	for _, strategy := range strategies {
		for _, port := range ports {
			xpath := strategy.getXPath(port)
			if node := xmlquery.FindOne(document, xpath); node != nil {
				domain = strategy.extract(node.InnerText())
				if domain != "" {
					usedStrategy = strategy.name
					break
				}
			}
		}
		if domain != "" {
			break
		}
	}

	if domain == "" {
		return "", fmt.Errorf("could not determine domain from nmap results")
	}

	domainBuilder := model.NewDomainBuilder()
	domainBuilder.WithName(domain)
	builtDomain := domainBuilder.Build()

	ctx := context.Background()
	addedDomainID, err := n.services.ProjectService.AddDomain(ctx, params.ProjectUID, &builtDomain)
	if err != nil {
		n.logger.Error("failed to create domain for host",
			"domain", domain,
			"ip", ip,
			"project", params.ProjectUID,
			"error", err)
		return "", err
	}

	n.logger.Info("created domain for host",
		"domain", domain,
		"ip", ip,
		"strategy", usedStrategy,
		"domainID", addedDomainID)

	return addedDomainID, nil
}

func extractDomainFromExtrainfo(info string) string {
	re := regexp.MustCompile(`Domain:\s*([a-zA-Z0-9.-]+)`)
	match := re.FindStringSubmatch(info)
	if len(match) > 1 {
		return strings.Replace(match[1], ".local0.", ".local", 1)
	}
	return ""
}

func extractDomainFromFQDN(fqdn string) string {
	if parts := strings.SplitN(fqdn, ".", 2); len(parts) == 2 {
		return parts[1]
	}
	return ""
}

func (n *NetworkExplorer) isHostDomainDiscovered(result serializable.Host) bool {
	return true
}

// BUILD DOMAIN

func (n *NetworkExplorer) buildDomainName(nmapResult scan.NmapScanResult) string {
	ports := []string{"389", "636", "3268", "3269"}

	ipAddr := "10.3.10.10"

	for _, port := range ports {
		xpath := fmt.Sprintf("//host/address[@addr='%s']/../ports/port[@portid='%s']/script[@id='ssl-cert']/table[@key='subject']/elem[@key='commonName']",
			ipAddr, port)

		value, err := nmapResult.QueryValue(xpath)
		if err == nil && value != "" {
			return value
		}

	}

	return ""
}

func (n *NetworkExplorer) buildServices(host serializable.Host, hostID string) {

	for _, port := range host.Ports.Port {
		if port.State.State == "open" {
			serviceBuilder := model.NewServiceBuilder()
			serviceBuilder.WithName(port.Service.Name)
			serviceBuilder.WithPort(port.Portid)
			service := serviceBuilder.Build()
			_, err := n.services.HostService.AddService(context.Background(), hostID, service)
			if err != nil {
				log.Printf("error creating service in module network explorer: %v", err)
				return
			}
		}

	}

}

func (n *NetworkExplorer) isDomainController(nmapResult scan.NmapScanResult, ip string) bool {
	document, err := nmapResult.GetXMLDocument()
	if err != nil {
		n.logger.Error(fmt.Sprintf("[Network Explorer] Error detecting domain controller: %v", err))
		return false
	}

	xpathBuilder := internal.NewXPathBuilder(ip)

	dcXPath := xpathBuilder.IsDomainController()

	if node := xmlquery.FindOne(document, dcXPath); node != nil {
		return true
	}

	dcPorts := map[string]bool{
		"53":   true, // DNS
		"88":   true, // Kerberos
		"389":  true, // LDAP
		"445":  true, // SMB
		"464":  true, // Kerberos password change
		"636":  true, // LDAPS
		"3268": true, // Global Catalog
		"3269": true, // Global Catalog over SSL
	}

	matchCount := 0

	for portID := range dcPorts {
		portXPath := fmt.Sprintf("%s/ports/port[@portid='%s' and state/@state='open']", xpathBuilder.Host(), portID)
		if node := xmlquery.FindOne(document, portXPath); node != nil {
			matchCount++

			if portID == "88" {
				return true
			}
		}
	}

	serviceTypes := []string{"ldap", "kerberos", "msrpc"}
	for _, serviceType := range serviceTypes {
		serviceXPath := fmt.Sprintf("%s/ports/port[state/@state='open']/service[@name='%s']", xpathBuilder.Host(), serviceType)
		nodes := xmlquery.Find(document, serviceXPath)
		matchCount += len(nodes)
	}

	return matchCount >= 3
}
