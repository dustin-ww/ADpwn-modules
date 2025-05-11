package internal

import "fmt"

// XPath-Konstanten für die Nmap-XML-Analyse
const (
	// Basis-XPath für Host-Informationen
	hostXPath = "//host[address/@addr='%s']"

	// Allgemeine Host-Informationen
	hostIPXPath    = "address/@addr"
	hostNameXPath  = "hostnames/hostname/@name"
	hostStateXPath = "status/@state"

	// Port- und Service-Informationen
	portsXPath            = "ports/port"
	openPortsXPath        = "ports/port[state/@state='open']"
	portStateXPath        = "state/@state"
	portNumberXPath       = "@portid"
	serviceNameXPath      = "service/@name"
	serviceProductXPath   = "service/@product"
	serviceExtraInfoXPath = "service/@extrainfo"

	// LDAP-spezifische Informationen
	ldapServiceXPath           = "service[@name='ldap']"
	ldapExtraInfoXPath         = "@extrainfo"
	ldapDomainInExtraInfoXPath = "service[@name='ldap']/@extrainfo"

	// SSL/TLS-Zertifikate
	sslCertXPath        = "script[@id='ssl-cert']"
	certSubjectXPath    = "table[@key='subject']/elem[@key='commonName']"
	certIssuerXPath     = "table[@key='issuer']/elem[@key='domainComponent']"
	certExtensionsXPath = "table[@key='extensions']/table/elem[contains(@value, 'DNS:')]"

	// Active Directory spezifische Dienste
	kerberosServiceXPath = "service[@name='kerberos']"
	smbServiceXPath      = "service[@name='microsoft-ds']"
	dnsServiceXPath      = "service[@name='domain']"
	globalCatalogXPath   = "service[@name='ldap'][@port='3268' or @port='3269']"
)

// XPathBuilder ermöglicht die einfache Erstellung von XPath-Ausdrücken für einen bestimmten Host
type XPathBuilder struct {
	hostIP string
}

// NewXPathBuilder erstellt einen neuen XPath-Builder für die angegebene IP-Adresse
func NewXPathBuilder(ip string) *XPathBuilder {
	return &XPathBuilder{hostIP: ip}
}

// Host gibt den Basis-XPath für den Host zurück
func (b *XPathBuilder) Host() string {
	return fmt.Sprintf(hostXPath, b.hostIP)
}

// PortWithID erstellt einen XPath für einen bestimmten Port
func (b *XPathBuilder) PortWithID(portID string) string {
	return fmt.Sprintf("%s/ports/port[@portid='%s']", b.Host(), portID)
}

// LDAPServiceOnPort erstellt einen XPath für den LDAP-Dienst auf einem bestimmten Port
func (b *XPathBuilder) LDAPServiceOnPort(portID string) string {
	return fmt.Sprintf("%s/%s", b.PortWithID(portID), ldapServiceXPath)
}

// LDAPExtraInfo erstellt einen XPath für die LDAP-Extra-Informationen auf einem bestimmten Port
func (b *XPathBuilder) LDAPExtraInfo(portID string) string {
	return fmt.Sprintf("%s/%s/%s", b.Host(), b.PortWithID(portID), ldapExtraInfoXPath)
}

// SSLCertCommonName erstellt einen XPath für den Common Name eines SSL-Zertifikats auf einem bestimmten Port
func (b *XPathBuilder) SSLCertCommonName(portID string) string {
	return fmt.Sprintf("%s/%s/%s", b.PortWithID(portID), sslCertXPath, certSubjectXPath)
}

// SSLCertDomainComponent erstellt einen XPath für die Domain-Komponente eines SSL-Zertifikats auf einem bestimmten Port
func (b *XPathBuilder) SSLCertDomainComponent(portID string) string {
	return fmt.Sprintf("%s/%s/%s", b.PortWithID(portID), sslCertXPath, certIssuerXPath)
}

// SSLCertSANDNS erstellt einen XPath für die SAN-DNS-Einträge eines SSL-Zertifikats auf einem bestimmten Port
func (b *XPathBuilder) SSLCertSANDNS(portID string) string {
	return fmt.Sprintf("%s/%s/%s", b.PortWithID(portID), sslCertXPath, certExtensionsXPath)
}

// IsDomainController erstellt einen XPath, der prüft, ob ein Host ein Domain Controller ist
func (b *XPathBuilder) IsDomainController() string {
	return fmt.Sprintf("%s[%s/port[@portid='88'] or count(%s/port[%s or %s or %s]) >= 3]",
		b.Host(),
		openPortsXPath,
		openPortsXPath,
		ldapServiceXPath,
		kerberosServiceXPath,
		smbServiceXPath)
}
