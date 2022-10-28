package healthcheck

import (
	"fmt"
	"strings"
	"time"
)

type CAValidityPeriod struct {
	Enabled               bool
	RootExpiries          map[ResultStatus]time.Duration
	IntermediateExpieries map[ResultStatus]time.Duration
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
	h.RootExpiries = make(map[ResultStatus]time.Duration, 3)
	h.IntermediateExpieries = make(map[ResultStatus]time.Duration, 3)

	parameters := []string{
		"root_expiry_critical",
		"intermediate_expiry_critical",
		"root_expiry_warning",
		"intermediate_expiry_warning",
		"root_expiry_informational",
		"intermediate_expiry_informational",
	}
	for _, parameter := range parameters {
		name_split := strings.Split(parameter, ",")
		if len(name_split) != 3 || name_split[1] != "expiry" {
			return fmt.Errorf("bad parameter: %v", parameter)
		}

		status, present := NameResultStatusMap[name_split[2]]
		if !present {
			return fmt.Errorf("bad parameter: %v's type %v isn't in name map", parameter, name_split[2])
		}

		value_raw, present := config[parameter]
		if !present {
			return fmt.Errorf("parameter not present in config; Executor should've handled this for us: %v", parameter)
		}

		value, err := time.ParseDuration(value_raw.(string))
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
