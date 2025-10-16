package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"recco-demo/authorizer/authentication"
	"regexp"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-xray-sdk-go/xray"

	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
)

var l *slog.Logger
var clientID string
var introspectionEndpoint string
var userInfoEndpoint string
var clientCertHeader string
var httpClient = http.DefaultClient
var errUnauthorized = errors.New("Unauthorized")
var denyAllAuthResponse = authentication.APIGatewayCustomAuthorizerResponse{
	PrincipalID: "user",
	PolicyDocument: events.APIGatewayCustomAuthorizerPolicy{
		Version: "2012-10-17",
		Statement: []events.IAMPolicyStatement{
			{
				Action:   []string{"execute-api:Invoke"},
				Effect:   "Deny",
				Resource: []string{"*"},
			},
		},
	},
}
var cert, key, ca []byte

type cnfResponse struct {
	X5TSha256 string `json:"x5t#S256"`
}

type introspectionResponse struct {
	Scope      string      `json:"scope"`
	Active     bool        `json:"active"`
	TokenType  string      `json:"token_type"`
	Exp        int         `json:"exp"`
	ClientID   string      `json:"client_id"`
	Subject    string      `json:"sub"`
	GivenName  string      `json:"given_name"`
	FamilyName string      `json:"family_name"`
	BirthDate  string      `json:"birthdate"`
	Address    string      `json:"address"`
	CNF        cnfResponse `json:"cnf,omitempty"`
}

// Helper to "normalise" the cert pem string
func normalisePEM(originalPEM string) string {
	// Remove cert sentinels
	var beginCert = `-----BEGIN CERTIFICATE-----`
	var endCert = `-----END CERTIFICATE-----`

	cleanCert := strings.ReplaceAll(originalPEM, "-----BEGIN CERTIFICATE-----", "")
	cleanCert = strings.ReplaceAll(cleanCert, endCert, "")
	cleanCert = strings.ReplaceAll(cleanCert, " ", "\n")

	// Put the sentinels back
	cleanCert = fmt.Sprintf("%s\n%s\n%s", beginCert, cleanCert, endCert)

	return cleanCert
}

// Helper to calculate the x5tsha256 for the client cert
func calculateX5TSha256(ctx context.Context, certData string) (string, error) {
	derBytes, _ := pem.Decode([]byte(certData))
	if derBytes == nil {
		return "", errors.New("failed to decode certificate")
	}
	cert, err := x509.ParseCertificate(derBytes.Bytes)
	if err != nil {
		l.ErrorContext(ctx, "error parsing certificate", slog.String("error", err.Error()))
		return "", err
	}
	l.InfoContext(ctx, "parsed client certificate", slog.Any("certificate", cert))

	fingerprint := sha256.Sum256(cert.Raw)

	b64 := base64.RawURLEncoding.EncodeToString(fingerprint[:])

	return b64, nil
}

// Help function to generate an IAM policy
func generatePolicy(principalID, resource string, lambdaCtx authentication.AuthorizerResponseContext) authentication.APIGatewayCustomAuthorizerResponse {
	authResponse := authentication.APIGatewayCustomAuthorizerResponse{PrincipalID: principalID}

	authResponse.PolicyDocument = events.APIGatewayCustomAuthorizerPolicy{
		Version: "2012-10-17",
		Statement: []events.IAMPolicyStatement{
			{
				Action:   []string{"execute-api:Invoke"},
				Effect:   "Allow",
				Resource: []string{resource},
			},
		},
	}
	// Optional output with custom properties of the String, Number or Boolean type.
	authResponse.Context = lambdaCtx
	return authResponse
}

func getTokenFromHeader(headers map[string]string) (string, error) {
	auth := headers["Authorization"]
	if auth == "" {
		auth = headers["authorization"]
	}
	rx := regexp.MustCompile(`^[bB]earer (.*)$`)
	token := rx.FindStringSubmatch(auth)
	if len(token) != 2 {
		return "", fmt.Errorf("unable to extract bearer token from header")
	}
	return token[1], nil
}

func introspectToken(ctx context.Context, token string, lambdaCtx *authentication.AuthorizerResponseContext) (*introspectionResponse, error) {
	l.InfoContext(ctx, "introspecting token")
	slog.InfoContext(ctx, "creating introspection request")
	form := url.Values{}
	form.Add("token", token)
	form.Add("client_id", os.Getenv("CLIENT_ID"))
	slog.InfoContext(ctx, "created introspection request", slog.Any("request", form))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, introspectionEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		slog.ErrorContext(ctx, "failed to invoke introspection", slog.String("error", err.Error()))
		return nil, errUnauthorized
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Build mTLS-enabled HTTP client
	clientCert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		log.Fatalf("failed to load client cert/key pair: %v", err)
	}
	rootCAs, err := x509.SystemCertPool()
	if rootCAs == nil || err != nil {
		rootCAs = x509.NewCertPool()
	}
	if ok := rootCAs.AppendCertsFromPEM(ca); !ok {
		log.Fatalf("failed to append CA bundle")
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      rootCAs,
		MinVersion:   tls.VersionTLS12,
	}
	mtlsClient := xray.Client(&http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	})

	l.InfoContext(ctx, "executing introspection request", slog.String("introspectionEndpoint", introspectionEndpoint))
	resp, err := mtlsClient.Do(req)
	if err != nil {
		slog.ErrorContext(ctx, "failed to call introspection", slog.String("error", err.Error()))
		return nil, errUnauthorized
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.ErrorContext(ctx, "unable to read introspection response", slog.String("error", err.Error()))
		return nil, errUnauthorized
	}

	if resp.StatusCode != http.StatusOK {
		slog.ErrorContext(ctx, "unexpected status on introspection", slog.Int("responseStatus", resp.StatusCode))
		return nil, errUnauthorized
	}

	iResp := introspectionResponse{}
	err = json.Unmarshal(b, &iResp)
	if err != nil {
		slog.ErrorContext(ctx, "error marshalling json", slog.String("error", err.Error()))
		return nil, errUnauthorized
	}
	lambdaCtx.AccessToken = authentication.Pointer(string(b))
	lambdaCtx.ClientID = &iResp.ClientID
	lambdaCtx.Scope = &iResp.Scope
	lambdaCtx.X5tsha256 = &iResp.CNF.X5TSha256

	l.InfoContext(ctx, "received introspection response", slog.Any("introspectionResponse", iResp))

	if !iResp.Active {
		slog.InfoContext(ctx, "token not active", slog.Any("introspectionResponse", iResp))
		return nil, errUnauthorized
	}
	slog.InfoContext(ctx, "token active", slog.Any("introspectionResponse", iResp))
	return &iResp, nil
}

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

func getUserInfo(ctx context.Context, token string, lambdaCtx *authentication.AuthorizerResponseContext) error {
	l.InfoContext(ctx, "preparing to retrieve user info response")
	userInfoReq, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoEndpoint, nil)
	if err != nil {
		return errUnauthorized
	}
	userInfoReq.Header.Add("content-type", "application/x-www-form-urlencoded")
	userInfoReq.Header.Add("authorization", fmt.Sprintf("Bearer %s", token))

	// Build mTLS-enabled HTTP client
	clientCert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		log.Fatalf("failed to load client cert/key pair: %v", err)
	}
	rootCAs, err := x509.SystemCertPool()
	if rootCAs == nil || err != nil {
		rootCAs = x509.NewCertPool()
	}
	if ok := rootCAs.AppendCertsFromPEM(ca); !ok {
		log.Fatalf("failed to append CA bundle")
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      rootCAs,
		MinVersion:   tls.VersionTLS12,
	}
	mtlsClient := xray.Client(&http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	})

	l.InfoContext(ctx, "retrieving user info response")
	resp, err := mtlsClient.Do(userInfoReq)
	if err != nil {
		l.ErrorContext(ctx, "unable to call user info endpoint", slog.String("error", err.Error()))
		return errUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		l.ErrorContext(ctx, "unexpected status on user info response", slog.Int("status", resp.StatusCode))
		return errUnauthorized
	}

	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		l.ErrorContext(ctx, "unable to read user info response body", slog.String("error", err.Error()))
		return errUnauthorized
	}

	l.InfoContext(ctx, "user info response", slog.Any("body", b))

	err = json.Unmarshal(b, &lambdaCtx.UserInfo)
	if err != nil {
		l.ErrorContext(ctx, "error unmarshalling user info", slog.String("error", err.Error()))
		return errUnauthorized
	}

	l.InfoContext(ctx, "user info retrieved", slog.Any("userInfo", *lambdaCtx.UserInfo))
	return nil
}

func validateCnf(ctx context.Context, iResp introspectionResponse, clientCert string) error {
	if clientCert == "" {
		l.ErrorContext(ctx, fmt.Sprintf("no %s found on request", clientCertHeader))
		return errUnauthorized
	}

	b64X5TS256, err := calculateX5TSha256(ctx, normalisePEM(clientCert))
	if err != nil {
		l.ErrorContext(ctx, "error calculating base64 thumbprint", slog.String("error", err.Error()))
		return errUnauthorized
	} else {
		l.InfoContext(ctx, "calculated base64 encoded sha256", slog.String("calculatedValue", b64X5TS256))
	}

	if b64X5TS256 != iResp.CNF.X5TSha256 {
		l.ErrorContext(ctx, "calculated and provided client certificate and token thumbprints do not match")
		return errUnauthorized
	}

	return nil
}

func handleRequest(ctx context.Context, event events.APIGatewayProxyRequest) (authentication.APIGatewayCustomAuthorizerResponse, error) {
	l.InfoContext(ctx, "authenticating request")
	l.InfoContext(ctx, "retrieving token from header")

	ssmCertName := os.Getenv("SSM_TRANSPORT_CERTIFICATE_NAME")
	ssmKeyName := os.Getenv("SSM_TRANSPORT_KEY_NAME")
	ssmCAName := os.Getenv("SSM_CA_TRUSTED_LIST_NAME")

	// Load PEM materials from SSM
	var err error
	cert, key, ca, err = loadTlsFromSSM(context.Background(), ssmCertName, ssmKeyName, ssmCAName)
	if err != nil {
		log.Fatalf("failed to load TLS materials from SSM: %v", err)
	}

	token, err := getTokenFromHeader(event.Headers)
	if err != nil {
		l.ErrorContext(ctx, "malformed authorization header", slog.String("error", err.Error()))
		return denyAllAuthResponse, errUnauthorized
	}

	lambdaCtx := authentication.AuthorizerResponseContext{}
	iResp, err := introspectToken(ctx, token, &lambdaCtx)
	if err != nil {
		l.ErrorContext(ctx, "unable to introspect token, rejecting", slog.String("error", err.Error()))
		return denyAllAuthResponse, errUnauthorized
	}
	if iResp.Subject != "" {
		lambdaCtx.Sub = authentication.Pointer(iResp.Subject)
	}

	if iResp.FamilyName != "" {
		lambdaCtx.FamilyName = authentication.Pointer(iResp.FamilyName)
	}

	if iResp.GivenName != "" {
		lambdaCtx.GivenName = authentication.Pointer(iResp.GivenName)
	}

	if iResp.BirthDate != "" {
		lambdaCtx.Birthdate = authentication.Pointer(iResp.BirthDate)
	}

	if iResp.Address != "" {
		lambdaCtx.Address = authentication.Pointer(iResp.Address)
	}

	slog.Info("lambda Context", slog.Any("lambdaCtx", lambdaCtx))
	ctx = context.Background()

	lc := event.RequestContext
	arn := fmt.Sprintf("arn:aws:execute-api:*:%s:%s/%s/%s/%s", lc.AccountID, lc.APIID, lc.Stage, "*", "*")

	principalID := clientID
	if iResp.Subject != "" {
		principalID = fmt.Sprintf("%s-%s", clientID, iResp.Subject)
	}

	if iResp.CNF.X5TSha256 != "" {
		// We have a CNF value in the token so check that the SHA256 for the cert in TLS-Certificate matches the CNF value
		clientCert := event.Headers[clientCertHeader]
		err := validateCnf(ctx, *iResp, clientCert)
		if err != nil {
			return denyAllAuthResponse, err
		}
	}

	return generatePolicy(principalID, arn, lambdaCtx), nil
}

func main() {
	_ = os.Setenv("AWS_XRAY_SDK_DISABLED", "TRUE")
	l = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx := context.Background()
	// ctx := slog.WithValue(context.Background(), slog.String("stage", "initialization"))

	httpClient = xray.Client(http.DefaultClient)

	for _, v := range []string{
		"INTROSPECTION_ENDPOINT",
		"USER_INFO_ENDPOINT",
		"CLIENT_ID",
	} {
		if _, found := os.LookupEnv(v); !found {
			msg := fmt.Sprintf("environment variable %s not set", v)
			l.ErrorContext(ctx, msg)
			panic(msg)
		}
	}

	clientID = os.Getenv("CLIENT_ID")
	introspectionEndpoint = os.Getenv("INTROSPECTION_ENDPOINT")
	userInfoEndpoint = os.Getenv("USER_INFO_ENDPOINT")
	clientCertHeader = os.Getenv("CLIENT_CERT_HEADER")

	_ = os.Unsetenv("AWS_XRAY_SDK_DISABLED")
	l.InfoContext(ctx, "lambda started")
	lambda.Start(handleRequest)
}
