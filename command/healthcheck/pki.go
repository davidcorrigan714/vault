package healthcheck

type CAValidityPeriod struct {

}

func (h *CAValidityPeriod) DefaultConfig() map[string]interface{} {
	return map[string]interface{}{
		"root_expiry_critical": "30d",
		"intermediate_expiry_critical": "30d",
		"root_expiry_warning": "365d",
		"intermediate_expiry_warning": "60d",
		"root_expiry_informational": "730d",
		"intermediate_expiry_informational": "180d"
	}
}

func (h *CAValidityPeriod) LoadConfig(config map[string]interface{}) error {

}
