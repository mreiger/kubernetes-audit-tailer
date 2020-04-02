package main

import (
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
	BindAddr       string   `validate:"required"`
	Port           int      `validate:"required"`
	AuditServePath string   `validate:"required"`
	ServerURLs     []string `validate:"required"`
	Token          string   `validate:"required"`
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
	splunkClient.SetHTTPClient(&http.Client{})

	auditController := audit.NewController(logger.Named("webhook-audit-controller"), splunkClient)

	http.HandleFunc(opts.AuditServePath, auditController.AuditEvent)

	addr := fmt.Sprintf("%s:%d", opts.BindAddr, opts.Port)
	logger.Infow("starting splunk audit webhook", "version", v.V.String(), "address", addr)
	err := http.ListenAndServe(addr, nil)
	if err != nil {
		logger.Errorw("failed to start audit webhook server", "error", err)
	}
}
