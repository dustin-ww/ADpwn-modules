package internal

import "fmt"

const (
	hostXPath = "//host[address/@addr='%s']"

	hostIPXPath    = "address/@addr"
	hostNameXPath  = "hostnames/hostname/@name"
	hostStateXPath = "status/@state"

	portsXPath            = "ports/port"
	openPortsXPath        = "ports/port[state/@state='open']"
	portStateXPath        = "state/@state"
	portNumberXPath       = "@portid"
	serviceNameXPath      = "service/@name"
	serviceProductXPath   = "service/@product"
	serviceExtraInfoXPath = "service/@extrainfo"

	ldapServiceXPath           = "service[@name='ldap']"
	ldapExtraInfoXPath         = "@extrainfo"
	ldapDomainInExtraInfoXPath = "service[@name='ldap']/@extrainfo"

	sslCertXPath        = "script[@id='ssl-cert']"
	certSubjectXPath    = "table[@key='subject']/elem[@key='commonName']"
	certIssuerXPath     = "table[@key='issuer']/elem[@key='domainComponent']"
	certExtensionsXPath = "table[@key='extensions']/table/elem[contains(@value, 'DNS:')]"

	kerberosServiceXPath = "service[@name='kerberos']"
	smbServiceXPath      = "service[@name='microsoft-ds']"
	dnsServiceXPath      = "service[@name='domain']"
	globalCatalogXPath   = "service[@name='ldap'][@port='3268' or @port='3269']"
)

type XPathBuilder struct {
	hostIP string
}

func NewXPathBuilder(ip string) *XPathBuilder {
	return &XPathBuilder{hostIP: ip}
}

func (b *XPathBuilder) Host() string {
	return fmt.Sprintf(hostXPath, b.hostIP)
}

func (b *XPathBuilder) Hostname() string {
	return fmt.Sprintf("%s/%s", b.Host(), hostNameXPath)
}

func (b *XPathBuilder) PortWithID(portID string) string {
	return fmt.Sprintf("%s/ports/port[@portid='%s']", b.Host(), portID)
}

func (b *XPathBuilder) LDAPServiceOnPort(portID string) string {
	return fmt.Sprintf("%s/%s", b.PortWithID(portID), ldapServiceXPath)
}

func (b *XPathBuilder) LDAPExtraInfo(portID string) string {
	return fmt.Sprintf("%s/%s/%s", b.Host(), b.PortWithID(portID), ldapExtraInfoXPath)
}

func (b *XPathBuilder) SSLCertCommonName(portID string) string {
	return fmt.Sprintf("%s/%s/%s", b.PortWithID(portID), sslCertXPath, certSubjectXPath)
}

func (b *XPathBuilder) SSLCertDomainComponent(portID string) string {
	return fmt.Sprintf("%s/%s/%s", b.PortWithID(portID), sslCertXPath, certIssuerXPath)
}

func (b *XPathBuilder) SSLCertSANDNS(portID string) string {
	return fmt.Sprintf("%s/%s/%s", b.PortWithID(portID), sslCertXPath, certExtensionsXPath)
}

func (b *XPathBuilder) IsDomainController() string {
	return fmt.Sprintf("%s[%s/port[@portid='88'] or count(%s/port[%s or %s or %s]) >= 3]",
		b.Host(),
		openPortsXPath,
		openPortsXPath,
		ldapServiceXPath,
		kerberosServiceXPath,
		smbServiceXPath)
}
