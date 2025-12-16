//nolint:depguard // main.go imports third-party packages required for webhook, metrics, and CLI functionality
package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	whhttp "github.com/slok/kubewebhook/v2/pkg/http"
	whlogrus "github.com/slok/kubewebhook/v2/pkg/log/logrus"
	metrics "github.com/slok/kubewebhook/v2/pkg/metrics/prometheus"
	whmodel "github.com/slok/kubewebhook/v2/pkg/model"
	wh "github.com/slok/kubewebhook/v2/pkg/webhook"
	"github.com/slok/kubewebhook/v2/pkg/webhook/mutating"
	"github.com/urfave/cli"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	kubernetesConfig "sigs.k8s.io/controller-runtime/pkg/client/config"
)

/* #nosec */
const (
	gtokenInitImage = "doitintl/gtoken:latest"
	tokenVolumeName = "gtoken-volume"
	tokenVolumePath = "/var/run/secrets/aws/token"
	tokenFileName   = "gtoken"

	awsRoleArnKey           = "amazonaws.com/role-arn"
	awsWebIdentityTokenFile = "AWS_WEB_IDENTITY_TOKEN_FILE"
	awsRoleArn              = "AWS_ROLE_ARN"
	awsRoleSessionName      = "AWS_ROLE_SESSION_NAME"
)

var (
	Version   = "dev"
	BuildDate = "unknown"
	testMode  = false
)

const (
	requestsCPU    = "5m"
	requestsMemory = "10Mi"
	limitsCPU      = "20m"
	limitsMemory   = "50Mi"
)

type mutatingWebhook struct {
	k8sClient  kubernetes.Interface
	image      string
	pullPolicy string
	volumeName string
	volumePath string
	tokenFile  string
}

var logger *log.Logger

// Generate a random string of a-z chars with len = l
func randomString(l int) string {
	if testMode {
		return strings.Repeat("0", l)
	}

	bytes := make([]byte, l)
	for i := 0; i < l; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(26))
		if err != nil {
			// log and fallback to 'a' character if random fails
			logger.WithError(err).Error("failed to generate random string, fallback to 'a'")
			bytes[i] = 'a'
			continue
		}
		bytes[i] = byte(n.Int64() + 97)
	}
	return string(bytes)
}

func newK8SClient() (kubernetes.Interface, error) {
	kubeConfig, err := kubernetesConfig.GetConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(kubeConfig)
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("ok")); err != nil {
		logger.WithError(err).Error("failed to write healthz response")
	}
}

func serveMetrics(ctx context.Context, addr string) {
	logger.Infof("Telemetry on http://%s", addr)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.WithError(err).Fatal("error serving telemetry")
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.WithError(err).Error("error shutting down telemetry server")
	} else {
		logger.Info("Telemetry server stopped gracefully")
	}
}

func handlerFor(config mutating.WebhookConfig, recorder wh.MetricsRecorder, logger *log.Logger) http.Handler {
	webhook, err := mutating.NewWebhook(config)
	if err != nil {
		logger.WithError(err).Fatal("error creating webhook")
	}

	measuredWebhook := wh.NewMeasuredWebhook(recorder, webhook)

	handler, err := whhttp.HandlerFor(whhttp.HandlerConfig{
		Webhook: measuredWebhook,
		Logger:  whlogrus.NewLogrus(log.NewEntry(logger)),
	})
	if err != nil {
		logger.WithError(err).Fatal("error creating webhook")
	}

	return handler
}

// check if K8s Service Account is annotated with AWS role
func (mw *mutatingWebhook) getAwsRoleArn(ctx context.Context, name, ns string) (roleArn string, ok bool, err error) {
	sa, err := mw.k8sClient.CoreV1().ServiceAccounts(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		// Log as error but don't terminate the webhook
		logger.WithFields(log.Fields{
			"service account": name,
			"namespace":       ns,
		}).WithError(err).Error("failed to get ServiceAccount")
		return "", false, err
	}

	roleArn, ok = sa.GetAnnotations()[awsRoleArnKey]
	return
}

func (mw *mutatingWebhook) mutateContainers(containers []corev1.Container, roleArn string) bool {
	if len(containers) == 0 {
		return false
	}

	for i := range containers {
		container := &containers[i]

		container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
			Name:      mw.volumeName,
			MountPath: mw.volumePath,
		})

		container.Env = append(container.Env,
			corev1.EnvVar{
				Name:  awsWebIdentityTokenFile,
				Value: fmt.Sprintf("%s/%s", mw.volumePath, mw.tokenFile),
			},
			corev1.EnvVar{
				Name:  awsRoleArn,
				Value: roleArn,
			},
			corev1.EnvVar{
				Name:  awsRoleSessionName,
				Value: fmt.Sprintf("gtoken-webhook-%s", randomString(16)),
			},
		)
	}
	return true
}

// mutatePod mutates pod containers by adding gtoken init/sidekick containers and volumes.
// Currently, it never returns an error. Kept error return for interface consistency.
//nolint:unparam // always returns nil, kept for future error handling
func (mw *mutatingWebhook) mutatePod(ctx context.Context, pod *corev1.Pod, ns string, dryRun bool) error {
	roleArn, ok, err := mw.getAwsRoleArn(ctx, pod.Spec.ServiceAccountName, ns)
	if err != nil {
		// just log and skip mutation instead of terminating webhook
		logger.WithFields(log.Fields{
			"pod":             pod.Name,
			"service account": pod.Spec.ServiceAccountName,
			"namespace":       ns,
		}).WithError(err).Warn("skipping pod mutation due to error fetching ServiceAccount")
		return nil
	}

	if !ok {
		logger.WithFields(log.Fields{
			"pod":             pod.Name,
			"service account": pod.Spec.ServiceAccountName,
		}).Debug("ServiceAccount has no AWS Role ARN annotation, skipping mutation")
		return nil
	}

	initMutated := mw.mutateContainers(pod.Spec.InitContainers, roleArn)
	contMutated := mw.mutateContainers(pod.Spec.Containers, roleArn)

	if (initMutated || contMutated) && !dryRun {
		pod.Spec.InitContainers = append([]corev1.Container{getGtokenContainer("generate-gcp-id-token",
			mw.image, mw.pullPolicy, mw.volumeName, mw.volumePath, mw.tokenFile, false)}, pod.Spec.InitContainers...)

		pod.Spec.Containers = append(pod.Spec.Containers, getGtokenContainer("update-gcp-id-token",
			mw.image, mw.pullPolicy, mw.volumeName, mw.volumePath, mw.tokenFile, true))

		pod.Spec.Volumes = append(pod.Spec.Volumes, getGtokenVolume(mw.volumeName))
	}

	return nil
}

func getGtokenVolume(volumeName string) corev1.Volume {
	return corev1.Volume{
		Name: volumeName,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{
				Medium: corev1.StorageMediumMemory,
			},
		},
	}
}

func getGtokenContainer(name, image, pullPolicy, volumeName, volumePath, tokenFile string, refresh bool) corev1.Container {
	return corev1.Container{
		Name:            name,
		Image:           image,
		ImagePullPolicy: corev1.PullPolicy(pullPolicy),
		Command:         []string{"/gtoken", fmt.Sprintf("--file=%s/%s", volumePath, tokenFile), fmt.Sprintf("--refresh=%t", refresh)},
		VolumeMounts: []corev1.VolumeMount{
			{Name: volumeName, MountPath: volumePath},
		},
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(requestsCPU),
				corev1.ResourceMemory: resource.MustParse(requestsMemory),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(limitsCPU),
				corev1.ResourceMemory: resource.MustParse(limitsMemory),
			},
		},
	}
}

func init() {
	logger = log.New()
	logger.SetLevel(log.WarnLevel)
	logger.SetFormatter(&log.TextFormatter{})
}

func before(c *cli.Context) error {
	switch level := strings.ToLower(c.GlobalString("log-level")); level {
	case "debug":
		logger.SetLevel(log.DebugLevel)
	case "info":
		logger.SetLevel(log.InfoLevel)
	case "warning":
		logger.SetLevel(log.WarnLevel)
	case "error":
		logger.SetLevel(log.ErrorLevel)
	case "fatal":
		logger.SetLevel(log.FatalLevel)
	case "panic":
		logger.SetLevel(log.PanicLevel)
	default:
		logger.SetLevel(log.WarnLevel)
	}

	if c.GlobalBool("json") {
		logger.SetFormatter(&log.JSONFormatter{})
	}
	return nil
}

func (mw *mutatingWebhook) podMutator(ctx context.Context, ar *whmodel.AdmissionReview, obj metav1.Object) (*mutating.MutatorResult, error) {
	switch v := obj.(type) {
	case *corev1.Pod:
		err := mw.mutatePod(ctx, v, ar.Namespace, ar.DryRun)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to mutate pod: %s", v.Name)
		}
		return &mutating.MutatorResult{MutatedObject: v}, nil
	default:
		return &mutating.MutatorResult{}, nil
	}
}

func runWebhookWithContext(ctx context.Context, c *cli.Context) error {
	k8sClient, err := newK8SClient()
	if err != nil {
		return err
	}

	webhook := mutatingWebhook{
		k8sClient:  k8sClient,
		image:      c.String("image"),
		pullPolicy: c.String("pull-policy"),
		volumeName: c.String("volume-name"),
		volumePath: c.String("volume-path"),
		tokenFile:  c.String("token-file"),
	}

	mutator := mutating.MutatorFunc(webhook.podMutator)
	metricsRecorder, err := metrics.NewRecorder(metrics.RecorderConfig{
		Registry: prometheus.DefaultRegisterer,
	})
	if err != nil {
		return err
	}

	podHandler := handlerFor(
		mutating.WebhookConfig{
			ID:      "init-gtoken-pods",
			Obj:     &corev1.Pod{},
			Mutator: mutator,
			Logger:  whlogrus.NewLogrus(log.NewEntry(logger)),
		},
		metricsRecorder,
		logger,
	)

	mux := http.NewServeMux()
	mux.Handle("/pods", podHandler)
	mux.Handle("/healthz", http.HandlerFunc(healthzHandler))

	telemetryAddress := c.String("telemetry-listen-address")
	listenAddress := c.String("listen-address")
	tlsCertFile := c.String("tls-cert-file")
	tlsPrivateKeyFile := c.String("tls-private-key-file")

	if telemetryAddress != "" {
		go serveMetrics(ctx, telemetryAddress)
	} else {
		mux.Handle("/metrics", promhttp.Handler())
	}

	srv := &http.Server{
		Addr:         listenAddress,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	serverErrCh := make(chan error, 1)
	go func() {
		if tlsCertFile == "" && tlsPrivateKeyFile == "" {
			logger.Infof("listening on http://%s", listenAddress)
			serverErrCh <- srv.ListenAndServe()
		} else {
			logger.Infof("listening on https://%s", listenAddress)
			serverErrCh <- srv.ListenAndServeTLS(tlsCertFile, tlsPrivateKeyFile)
		}
	}()

	select {
	case <-ctx.Done():
		logger.Info("termination signal received, shutting down servers...")
	case err := <-serverErrCh:
		if err != nil && err != http.ErrServerClosed {
			logger.WithError(err).Fatal("server failed")
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.WithError(err).Error("error shutting down webhook server")
	} else {
		logger.Info("Webhook server stopped gracefully")
	}

	return nil
}

func main() {
	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Printf("version: %s\n", c.App.Version)
		fmt.Printf("  build date: %s\n", BuildDate)
		fmt.Printf("  built with: %s\n", runtime.Version())
	}

	app := cli.NewApp()
	app.Name = "gtoken-webhook"
	app.Version = Version
	app.Authors = []cli.Author{{Name: "Alexei Ledenev", Email: "alexei.led@gmail.com"}}
	app.Usage = "gtoken-webhook is a Kubernetes mutation controller providing secure AWS access from GKE pods"
	app.Before = before
	app.Flags = []cli.Flag{
		cli.StringFlag{Name: "log-level", Usage: "set log level (debug, info, warning, error, fatal, panic)", Value: "warning", EnvVar: "LOG_LEVEL"},
		cli.BoolFlag{Name: "json", Usage: "produce log in JSON format", EnvVar: "LOG_JSON"},
	}
	app.Commands = []cli.Command{
		{
			Name: "server",
			Flags: []cli.Flag{
				cli.StringFlag{Name: "listen-address", Usage: "webhook server listen address", Value: ":8443"},
				cli.StringFlag{Name: "telemetry-listen-address", Usage: "dedicated Prometheus metrics listen address"},
				cli.StringFlag{Name: "tls-cert-file", Usage: "TLS certificate file"},
				cli.StringFlag{Name: "tls-private-key-file", Usage: "TLS private key file"},
				cli.StringFlag{Name: "image", Usage: "Docker image with secrets-init utility on board", Value: gtokenInitImage},
				cli.StringFlag{Name: "pull-policy", Usage: "Docker image pull policy", Value: string(corev1.PullIfNotPresent)},
				cli.StringFlag{Name: "volume-name", Usage: "mount volume name", Value: tokenVolumeName},
				cli.StringFlag{Name: "volume-path", Usage: "mount volume path", Value: tokenVolumePath},
				cli.StringFlag{Name: "token-file", Usage: "token file name", Value: tokenFileName},
			},
			Action: func(c *cli.Context) error {
				ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
				defer stop()
				return runWebhookWithContext(ctx, c)
			},
		},
	}

	logger.WithField("version", app.Version).Debug("running gtoken-webhook")

	if err := app.Run(os.Args); err != nil {
		logger.Fatal(err)
	}
}
