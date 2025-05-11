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
		domainUID = n.tryToBuildDomain(nmapResult, host.Address[0].Addr, params)

		// BUILD HOST
		hostUID = n.buildHost(nmapResult, params, domainUID)

		// BUILD SERVICES
		n.buildServices(host, hostUID)

	}
}

func (n *NetworkExplorer) buildHost(nmapResult scan.NmapScanResult, params *input.Parameter, domainUID string) string {
	/*host

	if domainUID == "" {
		domain, err := n.services.HostService.CreateWithUnknownDomain(context.Background())
		if err != nil {
			return ""
		}
	}*/
	return ""

}

func (n *NetworkExplorer) tryToBuildDomain(nmapResult scan.NmapScanResult, ip string, params *input.Parameter) string {
	document, err := nmapResult.GetXMLDocument()
	if err != nil {
		n.logger.Error(fmt.Sprintf("[Network Explorer] Error while parsing: %v", err))
		return ""
	}

	// Erstelle einen XPath-Builder für die gegebene IP
	xpathBuilder := internal.NewXPathBuilder(ip)

	ports := []string{"389", "636", "3268", "3269"}
	var domain string

	// 1. Domain from LDAP Info
	for _, port := range ports {
		xpath := xpathBuilder.LDAPExtraInfo(port)
		if node := xmlquery.FindOne(document, xpath); node != nil {
			domain = extractDomainFromExtrainfo(node.InnerText())
			if domain != "" {
				break
			}
		}
	}

	// 2. From Certificate Common Name
	if domain == "" {
		for _, port := range ports {
			xpath := xpathBuilder.SSLCertCommonName(port)
			if node := xmlquery.FindOne(document, xpath); node != nil {
				domain = extractDomainFromFQDN(node.InnerText())
				if domain != "" {
					break
				}
			}
		}
	}

	// 3. From SAN-DNS
	if domain == "" {
		for _, port := range ports {
			xpath := xpathBuilder.SSLCertSANDNS(port)
			if node := xmlquery.FindOne(document, xpath); node != nil {
				domain = extractDomainFromFQDN(strings.TrimPrefix(node.InnerText(), "DNS:"))
				if domain != "" {
					break
				}
			}
		}
	}

	// 4. From issuer domainComponent
	if domain == "" {
		for _, port := range ports {
			xpath := xpathBuilder.SSLCertDomainComponent(port)
			if node := xmlquery.FindOne(document, xpath); node != nil {
				domain = node.InnerText() + ".local"
				break
			}
		}
	}

	if domain == "" {
		n.logger.Info(fmt.Sprintf("Could not determine domain from nmap results for host %s", ip))
		return ""
	}

	domainBuilder := model.NewDomainBuilder()
	domainBuilder.WithName(domain)
	builtDomain := domainBuilder.Build()

	addedDomain, err := n.services.ProjectService.AddDomain(context.Background(), params.ProjectUID, &builtDomain)
	if err != nil {
		n.logger.Error(fmt.Sprintf("Error while creating domain for host: %s: %v", domain, err))
		return ""
	}

	n.logger.Info(fmt.Sprintf("Network Explorer Module created a domain: %s for host %s", domain, ip))
	return addedDomain
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

func (n *NetworkExplorer) buildHosts(nmapResult scan.NmapScanResult, params *input.Parameter) {

	/*for _, host := range nmapResult.GetNmapResult().Host {

		host, err := model.NewHostBuilder().Build()

		for _, port := range host.Ports.Port {

			xmlStr := nmapResult.GetRawOutput()
			doc, err := xmlquery.Parse(strings.NewReader(string(xmlStr)))

			if err != nil {
				log.Printf("ERRRRROR")
			}

			xpath := "//port[@portid='389']/script[@id='ssl-cert']/table[@key='subject']/elem[@key='commonName']"
			node := xmlquery.FindOne(doc, xpath)
			node.InnerText()

		}
	}*/

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

	// Prüfe direkt mit XPath, ob es sich um einen Domain Controller handelt
	dcXPath := xpathBuilder.IsDomainController()

	if node := xmlquery.FindOne(document, dcXPath); node != nil {
		return true
	}

	// Alternative Überprüfung: Zähle DC-typische Ports
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

	// Überprüfe offene Ports
	for portID := range dcPorts {
		portXPath := fmt.Sprintf("%s/ports/port[@portid='%s' and state/@state='open']", xpathBuilder.Host(), portID)
		if node := xmlquery.FindOne(document, portXPath); node != nil {
			matchCount++

			// Kerberos (Port 88) ist ein starker Indikator für einen DC
			if portID == "88" {
				return true
			}
		}
	}

	// Überprüfe Dienste
	serviceTypes := []string{"ldap", "kerberos", "msrpc"}
	for _, serviceType := range serviceTypes {
		serviceXPath := fmt.Sprintf("%s/ports/port[state/@state='open']/service[@name='%s']", xpathBuilder.Host(), serviceType)
		nodes := xmlquery.Find(document, serviceXPath)
		matchCount += len(nodes)
	}

	return matchCount >= 3
}
