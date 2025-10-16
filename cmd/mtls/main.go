package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

func main() {
	l := logger()
	slog.SetDefault(l)
	ctx := context.Background()

	for _, v := range []string{
		"PROXY_HOST_TARGET",
		"SSM_TRANSPORT_KEY_NAME",
		"SSM_TRANSPORT_CERTIFICATE_NAME",
		"SSM_CA_TRUSTED_LIST_NAME",
	} {
		if _, found := os.LookupEnv(v); !found {
			msg := fmt.Sprintf("environment variable %s not set", v)
			l.ErrorContext(ctx, msg)
			panic(msg)
		}
	}
	slog.InfoContext(ctx, "lambda started", slog.Any("stage", "initialization"))

	mux := http.NewServeMux()
	mux.Handle("/", reverseProxy())
	mux.Handle("/health", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	tlsConfig := tlsConfiguration()
	server := http.Server{
		Handler:           mux,
		ErrorLog:          slog.NewLogLogger(l.Handler(), slog.LevelError),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 30 * time.Second,
	}

	lnConfig := net.ListenConfig{}
	ln, err := lnConfig.Listen(context.Background(), "tcp", fmt.Sprintf(":%d", 443))
	if err != nil {
		os.Exit(1)
	}
	slog.Info("Listening on port 443")
	slog.Error("server error", slog.String("err", server.Serve(tls.NewListener(ln, tlsConfig)).Error()))
}

func reverseProxy() http.Handler {
	slog.Info("parsing proxy target", slog.Any("target", os.Getenv("PROXY_HOST_TARGET")))
	apiHost, err := url.Parse(os.Getenv("PROXY_HOST_TARGET"))
	if err != nil {
		slog.Error("unable to upstream url", slog.String("err", err.Error()))
		os.Exit(1)
	}
	// Create reverse proxies with custom director to add headers
	apiProxy := httputil.NewSingleHostReverseProxy(apiHost)
	origDirector := apiProxy.Director

	// Add custom Director to set required headers
	apiProxy.Director = func(req *http.Request) {
		origDirector(req)
		req.Host = apiHost.Host

		setCustomHeaders(req, apiHost)
	}
	apiProxyHandler := loggingMiddleware(apiProxy)
	apiProxyHandler = enforceAccessTokenMiddleware(apiProxyHandler)

	return apiProxyHandler
}

//nolint:gosec
func tlsConfiguration() *tls.Config {
	// Attempt to load from SSM if the required env vars are present.
	ssmCertName := os.Getenv("SSM_TRANSPORT_CERTIFICATE_NAME")
	ssmKeyName := os.Getenv("SSM_TRANSPORT_KEY_NAME")
	ssmCAName := os.Getenv("SSM_CA_TRUSTED_LIST_NAME")

	// Load PEM materials from SSM
	certPEM, keyPEM, caPEM, err := loadTlsFromSSM(context.Background(), ssmCertName, ssmKeyName, ssmCAName)
	if err != nil {
		log.Fatalf("failed to load TLS materials from SSM: %v", err)
	}

	// Build CA pool
	caPool := x509.NewCertPool()
	if ok := caPool.AppendCertsFromPEM(caPEM); !ok {
		log.Fatalf("failed to append CA certificates from SSM parameter %q", ssmCAName)
	}

	// Validate certificate and key
	serverCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatalf("failed to parse server certificate/key from SSM: %v", err)
	}

	return &tls.Config{
		// Only hosts starting with "matls-" require mTLS.
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			log.Printf("picking tls config for %s\n", hello.ServerName)
			cfg := &tls.Config{
				Certificates: []tls.Certificate{serverCert},
				ClientAuth:   tls.NoClientCert,
				MinVersion:   tls.VersionTLS12,
			}
			if strings.HasPrefix(hello.ServerName, "matls-") {
				log.Println("mtls is required")
				cfg.ClientAuth = tls.RequireAndVerifyClientCert
				cfg.ClientCAs = caPool
			}
			return cfg, nil
		},
	}
}

// Helpers to load TLS materials from AWS SSM Parameter Store.
func loadTlsFromSSM(ctx context.Context, certName, keyName, caName string) (certPEM, keyPEM, caPEM []byte, err error) {
	local := strings.ToLower(os.Getenv("AWS_LOCAL")) == "true"
	region := os.Getenv("REGION")

	awsCfg, _ := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(region),
	)

	var client *ssm.Client
	if local {
		// Configure SSM client directly without a custom resolver
		client = ssm.NewFromConfig(awsCfg, func(o *ssm.Options) {
			o.BaseEndpoint = aws.String("http://localstack.local:4566")
			o.Credentials = credentials.NewStaticCredentialsProvider("test", "test", "")
		})
	} else {
		client = ssm.NewFromConfig(awsCfg)
	}

	get := func(name string, decrypt bool) ([]byte, error) {
		slog.Info("loading cert from SSM", slog.String("name", name))
		out, e := client.GetParameter(ctx, &ssm.GetParameterInput{
			Name:           aws.String(name),
			WithDecryption: aws.Bool(decrypt),
		})
		if e != nil {
			return nil, e
		}
		if out.Parameter == nil || out.Parameter.Value == nil {
			return nil, fmt.Errorf("parameter %s is empty", name)
		}
		return []byte(*out.Parameter.Value), nil
	}

	certPEM, err = get(certName, true)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("get cert: %w", err)
	}
	keyPEM, err = get(keyName, true)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("get key: %w", err)
	}
	caPEM, err = get(caName, true)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("get ca: %w", err)
	}

	return certPEM, keyPEM, caPEM, nil
}

func loggingMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w}
		h.ServeHTTP(rec, r)
		if rec.status == 0 {
			rec.status = http.StatusOK
		}

		attrs := []slog.Attr{
			slog.String("remoteIP", r.RemoteAddr),
			slog.String("host", r.Host),
			slog.String("request", r.RequestURI),
			slog.String("query", r.URL.RawQuery),
			slog.String("method", r.Method),
			slog.String("status", fmt.Sprintf("%d", rec.status)),
			slog.String("userAgent", r.UserAgent()),
			slog.String("referer", r.Referer()),
		}
		slog.LogAttrs(r.Context(), slog.LevelInfo, "access log", attrs...)
	})
}

func setCustomHeaders(req *http.Request, target *url.URL) {
	slog.Info("request before transformation",
		slog.String("method", req.Method),
		slog.String("url", req.URL.String()),
		slog.String("scheme", req.URL.Scheme),
		slog.String("host", req.Host),
		slog.String("path", req.URL.Path),
		slog.Any("query", req.URL.Query()),
		slog.Any("headers", req.Header),
		// Avoid logging body by default
	)

	req.Header.Set("X-Forwarded-Proto", "https") // Adjust to "https" if using HTTPS
	req.Header.Set("Host", req.Host)
	req.Header.Set("X-Real-IP", getRemoteIP(req))
	req.Header.Set("X-Forwarded-For", getForwardedFor(req))

	// Extract and set the client's certificate and DN
	if len(req.TLS.PeerCertificates) > 0 {
		// The TLS Block Ensures that the correct ordering has taken place and that the leaf certificate will be at block 0
		clientCert := req.TLS.PeerCertificates[0]
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: clientCert.Raw,
		})
		// Base64 encode the certificate to ensure it's valid for HTTP headers
		certPEMString := strings.ReplaceAll(string(certPEM), "\n", " ")
		req.Header.Set("TLS-Certificate", certPEMString)
		req.Header.Set("X-Certificate-DN", clientCert.Subject.String())
		req.Header.Set("X-Certificate-Verify", "SUCCESS")
	}

	req.URL.Scheme = target.Scheme
	req.URL.Host = target.Host

	if target.RawQuery == "" || req.URL.RawQuery == "" {
		req.URL.RawQuery = target.RawQuery + req.URL.RawQuery
	} else {
		req.URL.RawQuery = target.RawQuery + "&" + req.URL.RawQuery
	}
	if _, ok := req.Header["User-Agent"]; !ok {
		// explicitly disable User-Agent so it's not set to default value
		req.Header.Set("User-Agent", "")
	}
	slog.Info("request after transformation",
		slog.String("method", req.Method),
		slog.String("url", req.URL.String()),
		slog.String("scheme", req.URL.Scheme),
		slog.String("host", req.Host),
		slog.String("path", req.URL.Path),
		slog.Any("query", req.URL.Query()),
		slog.Any("headers", req.Header),
		// Avoid logging body by default
	)
}

func getRemoteIP(req *http.Request) string {
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return ""
	}
	return ip
}

func getForwardedFor(req *http.Request) string {
	forwardedFor := req.Header.Get("X-Forwarded-For")
	if forwardedFor != "" {
		return forwardedFor + ", " + getRemoteIP(req)
	}
	return getRemoteIP(req)
}

func enforceAccessTokenMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessToken := getAccessToken(r)
		if accessToken == "" {
			slog.Error("No Authorization header, returning 401")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func getAccessToken(req *http.Request) string {
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		authHeader = req.Header.Get("authorization")
	}
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}
	return ""
}

func logger() *slog.Logger {
	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}
	handler := slog.NewJSONHandler(os.Stdout, opts)

	return slog.New(handler)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (rec *statusRecorder) WriteHeader(code int) {
	rec.status = code
	rec.ResponseWriter.WriteHeader(code)
}
