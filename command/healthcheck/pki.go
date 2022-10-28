package healthcheck

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/logical"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
)

type CAValidityPeriod struct {
	Enabled bool

	RootExpiries          map[ResultStatus]time.Duration
	IntermediateExpieries map[ResultStatus]time.Duration

	Issuers map[string]*x509.Certificate
}

func NewCAValidityPeriodCheck() Check {
	return &CAValidityPeriod{
		RootExpiries:          make(map[ResultStatus]time.Duration, 3),
		IntermediateExpieries: make(map[ResultStatus]time.Duration, 3),
		Issuers:               make(map[string]*x509.Certificate),
	}
}

func (h *CAValidityPeriod) Name() string {
	return "ca_validity_period"
}

func (h *CAValidityPeriod) DefaultConfig() map[string]interface{} {
	return map[string]interface{}{
		"root_expiry_critical":              "30d",
		"intermediate_expiry_critical":      "30d",
		"root_expiry_warning":               "365d",
		"intermediate_expiry_warning":       "60d",
		"root_expiry_informational":         "730d",
		"intermediate_expiry_informational": "180d",
	}
}

func (h *CAValidityPeriod) LoadConfig(config map[string]interface{}) error {
	parameters := []string{
		"root_expiry_critical",
		"intermediate_expiry_critical",
		"root_expiry_warning",
		"intermediate_expiry_warning",
		"root_expiry_informational",
		"intermediate_expiry_informational",
	}
	for _, parameter := range parameters {
		name_split := strings.Split(parameter, "_")
		if len(name_split) != 3 || name_split[1] != "expiry" {
			return fmt.Errorf("bad parameter: %v / %v / %v", parameter, len(name_split), name_split[1])
		}

		status, present := NameResultStatusMap[name_split[2]]
		if !present {
			return fmt.Errorf("bad parameter: %v's type %v isn't in name map", parameter, name_split[2])
		}

		value_raw, present := config[parameter]
		if !present {
			return fmt.Errorf("parameter not present in config; Executor should've handled this for us: %v", parameter)
		}

		value, err := parseutil.ParseDurationSecond(value_raw)
		if err != nil {
			return fmt.Errorf("failed to parse parameter (%v=%v): %w", parameter, value_raw, err)
		}

		if name_split[0] == "root" {
			h.RootExpiries[status] = value
		} else if name_split[0] == "intermediate" {
			h.IntermediateExpieries[status] = value
		} else {
			return fmt.Errorf("bad parameter: %v's CA type isn't root/intermediate: %v", parameters, name_split[0])
		}
	}

	h.Enabled = config["enabled"].(bool)

	return nil
}

func (h *CAValidityPeriod) FetchResources(e *Executor) error {
	// Check if the issuer is fetched yet.
	issuersRet, err := e.FetchIfNotFetched(logical.ListOperation, "/{{mount}}/issuers")
	if err != nil {
		return err
	}

	if len(issuersRet.ParsedCache) == 0 {
		var issuers []string
		for _, rawIssuerId := range issuersRet.Response.Data["keys"].([]interface{}) {
			issuers = append(issuers, rawIssuerId.(string))
		}
		issuersRet.ParsedCache["issuers"] = issuers
	}

	for _, issuer := range issuersRet.ParsedCache["issuers"].([]string) {
		issuerRet, err := e.FetchIfNotFetched(logical.ReadOperation, "/{{mount}}/issuer/"+issuer+"/json")
		if err != nil {
			return err
		}

		if len(issuerRet.ParsedCache) == 0 {
			// Need to parse out the issuer from its PEM format.
			pemBlock, _ := pem.Decode([]byte(issuerRet.Response.Data["certificate"].(string)))
			if pemBlock == nil {
				return fmt.Errorf("failed to parse issuer's PEM: %v", issuer)
			}

			cert, err := x509.ParseCertificate(pemBlock.Bytes)
			if err != nil {
				return fmt.Errorf("failed to parse certificate for issuer (%v): %w", issuer, err)
			}

			issuerRet.ParsedCache["certificate"] = cert
		}

		h.Issuers[issuer] = issuerRet.ParsedCache["certificate"].(*x509.Certificate)
	}

	return nil
}

func (h *CAValidityPeriod) Evaluate(e *Executor) (results []*Result, err error) {
	now := time.Now()

	for name, cert := range h.Issuers {
		var ret Result
		ret.Status = ResultOK
		ret.Endpoint = "/{{mount}}/issuer/" + name
		ret.Message = fmt.Sprintf("Issuer (%v)'s expiration (%v) is OK", name, cert.NotAfter.Format("2006-01-02"))

		hasSelfReference := bytes.Equal(cert.RawSubject, cert.RawIssuer)
		isSelfSigned := cert.CheckSignatureFrom(cert) == nil
		isRoot := hasSelfReference && isSelfSigned

		for _, criticality := range []ResultStatus{ResultCritical, ResultWarning, ResultInformational} {
			var d time.Duration
			if isRoot {
				d = h.RootExpiries[criticality]
			} else {
				d = h.IntermediateExpieries[criticality]
			}

			windowExpiry := now.Add(d)
			if cert.NotAfter.Before(windowExpiry) {
				ret.Status = criticality
				ret.Message = fmt.Sprintf("Issuer (%v)'s expiration (%v) is within the %v window of %v", name, cert.NotAfter.Format("2006-01-02"), ResultStatusNameMap[criticality], d.String())
				break
			}
		}

		results = append(results, &ret)
	}

	return
}
