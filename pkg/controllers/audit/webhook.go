package audit

import (
	// "encoding/base64"
	"io/ioutil"
	"net/http"
	"time"

	hec "github.com/fuyufjh/splunk-hec-go"

	"go.uber.org/zap"
)

// Controller that retrieves audit webhooks and reports event to the resource-sink
type Controller struct {
	logger *zap.SugaredLogger
	client hec.HEC
}

// NewController returns a new accounting controller
func NewController(logger *zap.SugaredLogger, client hec.HEC) *Controller {
	controller := &Controller{
		logger: logger,
		client: client,
	}
	return controller
}

// AuditEvent handles an audit event
func (c *Controller) AuditEvent(response http.ResponseWriter, request *http.Request) {
	Body, _ := ioutil.ReadAll(request.Body)
	c.logger.Infow("received audit event", "request", string(Body))
	// BodyString, err := base64.URLEncoding.DecodeString(string(BodyStringBase64))
	// if err != nil {
	// 	c.logger.Errorw("error base64 decoding the body", "error", err)
	// 	response.WriteHeader(http.StatusInternalServerError)
	// 	return
	// }
	// c.logger.Infow("received audit event", "request base64decoded", BodyString)

	event := hec.NewEvent(string(Body))
	event.SetHost("HOST")
	event.SetTime(time.Now())
	event.SetSource("SOURCE")
	event.SetSourceType("SOURCETYPE")

	c.logger.Infow("HEC Event",
		"Host", event.Host,
		"Time", event.Time,
		"Source", event.Source,
		"Sourcetype", event.SourceType,
		// event.Fields.(string),
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
