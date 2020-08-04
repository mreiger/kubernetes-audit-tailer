package audit

import (
	// "encoding/base64"
	"io/ioutil"
	"net/http"

	hec "github.com/fuyufjh/splunk-hec-go"

	"go.uber.org/zap"
)

// Controller that retrieves audit webhooks and reports event to the resource-sink
type Controller struct {
	logger *zap.SugaredLogger
	client hec.HEC
	host   string
}

// NewController returns a new accounting controller
func NewController(logger *zap.SugaredLogger, client hec.HEC, host string) *Controller {
	controller := &Controller{
		logger: logger,
		client: client,
		host:   host,
	}
	return controller
}

// AuditEvent handles an audit event
func (c *Controller) AuditEvent(response http.ResponseWriter, request *http.Request) {
	body, _ := ioutil.ReadAll(request.Body)
	c.logger.Infow("received audit event", "request", string(body))

	c.logger.Infow("Splunk host:", "c.host=", c.host)
	event := hec.NewEvent(string(body))
	if c.host != "" {
		event.SetHost(c.host)
	}
	// event.SetTime(time.Now()) // Splunk sets the time if not specified here
	// event.SetSource("SOURCE") // Could set this but Splunk defaults are probably good enough
	// event.SetSourceType("SOURCETYPE") // dito

	c.logger.Infow("HEC Event",
		"Host", event.Host,
		"Time", event.Time,
		"Source", event.Source,
		"Sourcetype", event.SourceType,
		"Event", event.Event.(string),
	)

	err := c.client.WriteEvent(event)
	if err != nil {
		c.logger.Errorw("error sending event to splunk", "error", err)
		response.WriteHeader(http.StatusInternalServerError)
		return
	}

	response.WriteHeader(http.StatusOK)
}
