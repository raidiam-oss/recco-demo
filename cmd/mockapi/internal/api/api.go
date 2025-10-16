package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"strings"

	"recco-demo/cmd/mockapi/internal/dynamodbhelper"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/awslabs/aws-lambda-go-api-proxy/core"
)

// scopes required by each endpoint
const (
	customerScope = "customer"
	energyScope   = "energy"
)

var (
	dynamoDbClient *dynamodb.Client
)

func Handler(l *slog.Logger) http.Handler {
	local := strings.ToLower(os.Getenv("AWS_LOCAL")) == "true"
	region := os.Getenv("REGION")
	awsCfg, _ := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(region),
	)

	if local {
		dynamoDbClient = dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) {
			o.BaseEndpoint = aws.String("http://localstack.local:4566")
			o.Credentials = credentials.NewStaticCredentialsProvider("test", "test", "")
		})
	} else {
		dynamoDbClient = dynamodb.NewFromConfig(awsCfg)
	}

	// creates mock data in dynamodb if the POPULATE_DB env variable is set to true
	populateDb(context.Background(), dynamoDbClient, l)

	mux := http.NewServeMux()
	mux.Handle("/recco/customer/v1/customer", requireScopes(customerScope)(customerHandle()))
	mux.Handle("/recco/energy/v1/energy", requireScopes(energyScope)(energyHandle()))

	return mux
}

// customerHandle handles the request for customer data.
// - 200 with the customer data as json.
// - 404 if no energy data found.
// - 500 if error retrieving data from dynamodb.
func customerHandle() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// getting the user info from the authorizer context
		// returning directly, but in a production environment, we would match these unique identifiers to a user in our database and return a more complex data
		c := userInfoFromAuthorizer(r)
		if c.ID == "" {
			w.WriteHeader(http.StatusNotFound)
		}

		RespondWithJson(context.Background(), slog.New(slog.NewJSONHandler(os.Stdout, nil)), w, c)
	})
}

// energyHandle handles the request for energy data.
// - 200 with the energy data as json.
// - 404 if no energy data found.
// - 500 if error retrieving data from dynamodb.
//
//nolint:gosec
func energyHandle() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ids of energys in dynamodb
		// as per request it will return random energy
		customerIDs := []string{
			"a7b749d6-5384-4530-97c7-7443587b1e44",
			"28f0368f-89e9-4bc7-a520-c2adfd457f60",
			"f47ac10b-58cc-4372-a567-0e02b2c3d479",
			"6ba7b810-9dad-11d1-80b4-00c04fd430c8",
		}
		randomUUID := customerIDs[rand.IntN(len(customerIDs))]

		var energy Energy
		err := dynamodbhelper.Get(context.Background(), dynamoDbClient, randomUUID, &energy)
		if err != nil {
			slog.Error("failed to get data from dynamodb", slog.String("error", err.Error()))
			w.WriteHeader(http.StatusInternalServerError)
		}

		if energy.ID == "" {
			w.WriteHeader(http.StatusNotFound)
		}

		RespondWithJson(context.Background(), slog.New(slog.NewJSONHandler(os.Stdout, nil)), w, energy)
	})
}

// requireScopes validates the access token ane ensures all required scopes are present.
// - 401 if Authorization header missing, token invalid, or introspection inactive.
// - 403 if token active but lacks required scopes.
func requireScopes(required ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 1) Try to get scopes from API Gateway authorizer context
			scopes := scopesFromAuthorizer(r)
			log.Println("scopes from authorizer:", scopes)
			// 2) If not found (e.g., local), fall back to Authorization header parsing
			if len(scopes) == 0 {
				auth := r.Header.Get("Authorization")
				if auth == "" || !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				accessToken := strings.TrimSpace(auth[len("Bearer "):])
				var err error
				scopes, err = getScopes(accessToken)
				if err != nil {
					// Could not parse token or scopes, treat as unauthorized
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
			}

			slog.Info("scopes:", slog.Any("scopes", scopes))
			if !containsAllScopes(scopes, required) {
				oBytes, err := json.Marshal(struct {
					Message string `json:"message"`
				}{Message: "scope not allowed"})
				if err != nil {
					slog.Error("error marshalling response: ", slog.Any("error", err))
					w.WriteHeader(http.StatusInternalServerError)
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, err = w.Write(oBytes)
				if err != nil {
					return
				}
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func userInfoFromAuthorizer(r *http.Request) Customer {
	if v1, ok := core.GetAPIGatewayContextFromContext(r.Context()); ok && v1.Authorizer != nil {
		var sub, givenName, familyName, dob, address string

		if s, ok := v1.Authorizer["sub"].(string); ok && s != "" {
			sub = s
		}
		if gn, ok := v1.Authorizer["given_name"].(string); ok && gn != "" {
			givenName = gn
		}
		if fn, ok := v1.Authorizer["family_name"].(string); ok && fn != "" {
			familyName = fn
		}
		if b, ok := v1.Authorizer["birthdate"].(string); ok && b != "" {
			dob = b
		}
		if a, ok := v1.Authorizer["address"].(string); ok && a != "" {
			address = a
		}

		return Customer{
			ID:        sub,
			FirstName: givenName,
			LastName:  familyName,
			DOB:       dob,
			Address:   address,
		}
	}

	return Customer{}
}

// scopesFromAuthorizer extracts the space-delimited "scope" from API Gateway authorizer context.
func scopesFromAuthorizer(r *http.Request) []string {
	if v1, ok := core.GetAPIGatewayContextFromContext(r.Context()); ok && v1.Authorizer != nil {
		log.Println("authorizer:", v1.Authorizer)
		if s, ok := v1.Authorizer["scope"].(string); ok && s != "" {
			return strings.Fields(s)
		}
	}
	return nil
}

func getScopes(token string) ([]string, error) {
	var payload struct {
		Active      bool           `json:"active"`
		Scope       string         `json:"scope"`       // space-delimited
		Scopes      []string       `json:"scopes"`      // optional alt
		Permissions []string       `json:"permissions"` // optional alt
		Extra       map[string]any `json:"-"`
	}

	if err := json.Unmarshal([]byte(token), &payload); err != nil {
		return nil, err
	}

	// Prefer explicit arrays if present, otherwise split the space-delimited string.
	switch {
	case len(payload.Scopes) > 0:
		return payload.Scopes, nil
	case len(payload.Permissions) > 0:
		return payload.Permissions, nil
	default:
		return splitScopes(payload.Scope), nil
	}
}

func splitScopes(s string) []string {
	fields := strings.Fields(s)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

func containsAllScopes(have []string, need []string) bool {
	set := make(map[string]struct{}, len(have))
	for _, s := range have {
		set[s] = struct{}{}
	}
	for _, req := range need {
		if _, ok := set[req]; !ok {
			return false
		}
	}
	return true
}

// RespondWithJson writes the given object as json to the response writer.
func RespondWithJson(ctx context.Context, l *slog.Logger, w http.ResponseWriter, o any) {
	l.InfoContext(ctx, "parsing result to return as json", slog.Any("result", o))
	oBytes, err := json.Marshal(o)
	if err != nil {
		l.ErrorContext(ctx, "error marshalling response: ", slog.Any("error", err))
		w.WriteHeader(http.StatusInternalServerError)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(oBytes)
	if err != nil {
		l.ErrorContext(ctx, "error sending response: ", slog.Any("error", err))
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// populateDb creates mock data in dynamodb if the POPULATE_DB env variable is set to true.
//
//nolint:gosec
func populateDb(ctx context.Context, client *dynamodb.Client, l *slog.Logger) {
	if os.Getenv("POPULATE_DB") == "true" {
		IDs := []string{
			"a7b749d6-5384-4530-97c7-7443587b1e44",
			"28f0368f-89e9-4bc7-a520-c2adfd457f60",
			"f47ac10b-58cc-4372-a567-0e02b2c3d479",
			"6ba7b810-9dad-11d1-80b4-00c04fd430c8",
		}
		energyTypes := []string{"solar", "gas", "power"}

		for _, ID := range IDs {
			err := dynamodbhelper.Save(ctx, client, Energy{
				ID:         ID,
				CustomerId: "123e4567-e89b-12d3-a456-426614174000",
				EnergyType: energyTypes[rand.IntN(len(energyTypes))],
				Price:      fmt.Sprintf("%.2f", rand.Float64()),
				Date:       fmt.Sprintf("%d-%02d-%02d", 2024+rand.IntN(2), rand.IntN(12)+1, rand.IntN(28)+1),
			})
			if err != nil {
				l.ErrorContext(ctx, "failed to save data to dynamodb", slog.String("error", err.Error()))
				return
			}
		}

		l.InfoContext(ctx, "saved data to dynamodb")
	}
}
