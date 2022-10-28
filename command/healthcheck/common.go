/*
 * The healthcheck package attempts to allow generic checks of arbitrary
 * engines, while providing a common framework with some performance
 * efficiencies in mind.
 *
 * The core of this package is the Executor context; a caller would
 * provision a set of checks, an API client, and a configuration,
 * which the executor would use to decide which checks to execute
 * and how.
 *
 * Checks are based around a series of remote paths that are fetched by
 * the client; these are broken into two categories: static paths, which
 * can always be fetched; and dynamic paths, which the check fetches based
 * on earlier results.
 *
 * For instance, a basic PKI CA lifetime check will have static fetch against
 * the list of CAs, and a dynamic fetch, using that earlier list, to fetch the
 * PEMs of all CAs.
 *
 * This allows health checks to share data: many PKI checks will need the
 * issuer list and so repeatedly fetching this may result in a performance
 * impact.
 */

package healthcheck

import (
	"github.com/hashicorp/vault/sdk/logical"
)

type Executor interface {

}

type PathFetch struct {
	Operation      logical.Operation
	Path           string
	RawResponse    []byte
	ParsedRespones interface{}
}

func (p *PathFetch) Execute(e Executor) error {
	return nil
}

type Check interface {
    Name() string

    DefaultConfig() map[string]interface{}
    LoadConfig(config map[string]interface{}) error

	StaticPaths() []string
	DynamicPaths(e Executor) ([]PathFetch, error)

	Evaluate(e Executor) ([]Result, error)
}

type Result struct {
    Status ResultStatus `json:"status"`
    Endpoint string `json:"endpoint,omitempty"`
    Message string `json:"message,omitempty"`
}
