package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"go.uber.org/zap"

	hec "github.com/fuyufjh/splunk-hec-go"
	"github.com/metal-stack/v"

	"github.com/metal-stack/kubernetes-splunk-audit-webhook/pkg/controllers/audit"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/go-playground/validator.v9"
)

const (
	cfgFileType = "yaml"
	moduleName  = "splunk-audit-webhook"
)

var (
	cfgFile string
	logger  *zap.SugaredLogger
)

// Opts is required in order to have proper validation for args from cobra and viper.
// this is because MarkFlagRequired from cobra does not work well with viper, see:
// https://github.com/spf13/viper/issues/397
type Opts struct {
	BindAddr       string
	Port           int
	AuditServePath string   `validate:"required"`
	ServerURLs     []string `validate:"required"`
	Token          string   `validate:"required"`
	InsecureCert   bool
	ClientTLSKey   string
	ClientTLSCert  string
	WebhookTLSKey  string
	WebhookTLSCert string
}

var cmd = &cobra.Command{
	Use:     moduleName,
	Short:   "a webhook that forwards audit events to splunk",
	Version: v.V.String(),
	Run: func(cmd *cobra.Command, args []string) {
		initLogging()
		initConfig()
		opts, err := initOpts()
		if err != nil {
			logger.Errorw("unable to init options", "error", err)
			return
		}
		run(opts)
	},
}

func init() {
	cmd.PersistentFlags().StringP("log-level", "", "info", "sets the application log level")
	cmd.Flags().StringVarP(&cfgFile, "config", "c", "", "alternative path to config file")

	cmd.Flags().StringP("bind-addr", "", "127.0.0.1", "the bind addr of the audit server")
	cmd.Flags().IntP("port", "", 3000, "the port to serve on")
	cmd.Flags().StringP("audit-serve-path", "", "/audit", "the path on which the server serves audit requests")

	cmd.Flags().StringSliceP("server-urls", "", []string{}, "splunk server urls (comma-separated")
	cmd.Flags().StringP("token", "", "", "the token to authenticate at the splunk servers")

	cmd.Flags().BoolP("insecure-cert", "", false, "whether to skip certificate validation")

	cmd.Flags().StringP("client-tls-key", "", "", "the path to the tls key file for client authentication to the splunk server with client certificate")
	cmd.Flags().StringP("client-tls-cert", "", "", "the path to the tls certificate file for client authentication to the splunk server with client certificate")

	cmd.Flags().StringP("webhook-tls-key", "", "", "the path to the tls key file for the webhook web server")
	cmd.Flags().StringP("webhook-tls-cert", "", "", "the path to the tls certificate file for the webhook web server")

	err := viper.BindPFlags(cmd.Flags())
	if err != nil {
		logger.Errorw("unable to construct root command", "error", err)
		os.Exit(1)
	}
}

func initOpts() (*Opts, error) {
	opts := &Opts{
		BindAddr:       viper.GetString("bind-addr"),
		Port:           viper.GetInt("port"),
		AuditServePath: viper.GetString("audit-serve-path"),
		ServerURLs:     viper.GetStringSlice("server-urls"),
		Token:          viper.GetString("token"),
		InsecureCert:   viper.GetBool("insecure-cert"),
		ClientTLSKey:   viper.GetString("client-tls-key"),
		ClientTLSCert:  viper.GetString("client-tls-cert"),
		WebhookTLSKey:  viper.GetString("webhook-tls-key"),
		WebhookTLSCert: viper.GetString("webhook-tls-cert"),
	}

	validate := validator.New()
	err := validate.Struct(opts)
	if err != nil {
		return nil, err
	}

	return opts, nil
}

func main() {
	if err := cmd.Execute(); err != nil {
		logger.Errorw("failed executing root command", "error", err)
		os.Exit(1)
	}
}

func initConfig() {
	viper.SetEnvPrefix("SPLUNK_AUDIT_WEBHOOK")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	viper.SetConfigType(cfgFileType)

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
		if err := viper.ReadInConfig(); err != nil {
			logger.Errorw("Config file path set explicitly, but unreadable", "error", err)
			os.Exit(1)
		}
	} else {
		viper.SetConfigName("config")
		viper.AddConfigPath("/etc/" + moduleName)
		viper.AddConfigPath("$HOME/." + moduleName)
		viper.AddConfigPath(".")
		if err := viper.ReadInConfig(); err != nil {
			usedCfg := viper.ConfigFileUsed()
			if usedCfg != "" {
				logger.Errorw("Config file unreadable", "config-file", usedCfg, "error", err)
				os.Exit(1)
			}
		}
	}

	usedCfg := viper.ConfigFileUsed()
	if usedCfg != "" {
		logger.Infow("Read config file", "config-file", usedCfg)
	}
}

func initLogging() {
	level := zap.InfoLevel

	if viper.IsSet("log-level") {
		err := level.UnmarshalText([]byte(viper.GetString("log-level")))
		if err != nil {
			log.Fatalf("can't initialize zap logger: %v", err)
		}
	}

	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(level)

	l, err := cfg.Build()
	if err != nil {
		log.Fatalf("can't initialize zap logger: %v", err)
	}

	logger = l.Sugar()
}

func run(opts *Opts) {
	splunkClient := hec.NewCluster(
		opts.ServerURLs,
		opts.Token,
	)

	if opts.ClientTLSCert != "" && opts.ClientTLSKey != "" {
		logger.Infow("getting client certificates from file", "Certificate", opts.ClientTLSCert, "Key", opts.ClientTLSKey)
		clientCert, err := tls.LoadX509KeyPair(opts.ClientTLSCert, opts.ClientTLSKey)
		if err != nil {
			logger.Errorw("failed to load client certificate and key", "Certificate", opts.ClientTLSCert, "Key", opts.ClientTLSKey, "error", err)
		}
		splunkClient.SetHTTPClient(&http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: opts.InsecureCert,
				Certificates:       []tls.Certificate{clientCert},
			}}})
	} else {
		splunkClient.SetHTTPClient(&http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: opts.InsecureCert,
			}}})
	}

	auditController := audit.NewController(logger.Named("webhook-audit-controller"), splunkClient)

	http.HandleFunc(opts.AuditServePath, auditController.AuditEvent)

	addr := fmt.Sprintf("%s:%d", opts.BindAddr, opts.Port)
	if opts.WebhookTLSCert != "" && opts.WebhookTLSKey != "" {
		logger.Infow("starting splunk audit TLS webhook", "version", v.V.String(), "address", addr, "Cert", opts.WebhookTLSCert, "Key", opts.WebhookTLSKey)
		err := http.ListenAndServeTLS(addr, opts.WebhookTLSCert, opts.WebhookTLSKey, nil)
		if err != nil {
			logger.Errorw("failed to start audit webhook TLS server", "error", err)
		}
	} else {
		logger.Infow("starting splunk audit plain webhook", "version", v.V.String(), "address", addr)
		err := http.ListenAndServe(addr, nil)
		if err != nil {
			logger.Errorw("failed to start audit webhook plain http server", "error", err)
		}
	}
}
