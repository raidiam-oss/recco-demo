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
	"time"

	"recco-demo/cmd/mockapi/internal/dynamodbhelper"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/awslabs/aws-lambda-go-api-proxy/core"
	"github.com/google/uuid"
)

// scopes required by each endpoint
const (
	customerScope = "customer"
	energyScope   = "energy"
	readingsScope = "readings"
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
	mux.Handle("/recco/readings/v1/readings/{mpxn}/{start_date}/{end_date}", requireScopes(readingsScope)(readingHandle()))

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

// readingHandle handles the request for meter reading data within a specified date range.
// Validates path parameters (mpxn, start_date, end_date) and queries DynamoDB for matching readings.
// - 200 with readings data as JSON array wrapped in a "data" field.
// - 400 if required parameters missing, mpxn not a valid UUID, dates not in ISO 8601 format, or start_date >= end_date.
// - 404 if no readings found for the given criteria.
// - 500 if error retrieving data from DynamoDB.
func readingHandle() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract path variables
		mpxn := r.PathValue("mpxn")
		startDate := r.PathValue("start_date")
		endDate := r.PathValue("end_date")

		// Log the extracted values
		slog.Info("reading request received",
			slog.String("mpxn", mpxn),
			slog.String("start_date", startDate),
			slog.String("end_date", endDate))

		// Validate required parameters
		if mpxn == "" || startDate == "" || endDate == "" {
			respondWithError(w, http.StatusBadRequest, "required_fields", "mpxn, start_date, and end_date are required")
			return
		}

		// Validate mpxn is a valid UUID
		if _, err := uuid.Parse(mpxn); err != nil {
			respondWithError(w, http.StatusBadRequest, "invalid_mpxn_format", "mpxn must be a valid UUID")
			return
		}

		// Validate start_date is ISO 8601
		startTime, err := time.Parse(time.RFC3339, startDate)
		if err != nil {
			respondWithError(w, http.StatusBadRequest, "invalid_date_format", "start_date must be in ISO 8601 format (e.g., 2024-01-01T00:00:00Z)")
			return
		}

		// Validate end_date is ISO 8601
		endTime, err := time.Parse(time.RFC3339, endDate)
		if err != nil {
			respondWithError(w, http.StatusBadRequest, "invalid_date_format", "end_date must be in ISO 8601 format (e.g., 2024-01-31T23:59:59Z)")
			return
		}

		// Validate start_date < end_date
		if !startTime.Before(endTime) {
			respondWithError(w, http.StatusBadRequest, "invalid_date_range", "start_date must be before end_date")
			return
		}

		// Query readings by mpxn and date range
		var readings []Reading
		err = dynamodbhelper.QueryByDateRange(
			context.Background(),
			dynamoDbClient,
			"readings",
			"mpxn",
			mpxn,
			"ts",
			startDate,
			endDate,
			&readings,
		)
		if err != nil {
			slog.Error("failed to query readings from dynamodb", slog.String("error", err.Error()))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if len(readings) == 0 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// ReadingsResponse wraps the readings array in a data field
		type ReadingsResponse struct {
			Data []Reading `json:"data"`
		}
		RespondWithJson(context.Background(), slog.New(slog.NewJSONHandler(os.Stdout, nil)), w, ReadingsResponse{Data: readings})
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
					respondWithError(w, http.StatusUnauthorized, "insufficient_scope", fmt.Sprintf("The token provided does not contain the required scope: %s", required))
					return
				}
				accessToken := strings.TrimSpace(auth[len("Bearer "):])
				var err error
				scopes, err = getScopes(accessToken)
				if err != nil {
					// Could not parse token or scopes, treat as unauthorized
					respondWithError(w, http.StatusUnauthorized, "insufficient_scope", fmt.Sprintf("The token provided does not contain the required scope: %s", required))
					return
				}
			}

			slog.Info("scopes:", slog.Any("scopes", scopes))
			if !containsAllScopes(scopes, required) {
				respondWithError(w, http.StatusUnauthorized, "insufficient_scope", fmt.Sprintf("The token provided does not contain the required scope: %s", required))
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

// respondWithError writes an error response as JSON
//
//nolint:errcheck
func respondWithError(w http.ResponseWriter, statusCode int, code string, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": message,
	})
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

		if err := dynamodbhelper.DeleteAll(ctx, client, "readings"); err != nil {
			l.ErrorContext(ctx, "failed to clear readings table", slog.String("error", err.Error()))
		}

		readings := []struct {
			mpxn string
			ts   string
			typ  string
		}{
			{"f47ac10b-58cc-4372-a567-0e02b2c3d479", "2025-01-15T08:30:00Z", "A"},
			{"f47ac10b-58cc-4372-a567-0e02b2c3d479", "2025-02-15T09:45:00Z", "A"},
			{"f47ac10b-58cc-4372-a567-0e02b2c3d479", "2025-03-15T10:20:00Z", "A"},
			{"f47ac10b-58cc-4372-a567-0e02b2c3d479", "2025-04-15T11:30:00Z", "A"},
			{"f47ac10b-58cc-4372-a567-0e02b2c3d479", "2025-05-15T12:45:00Z", "A"},
			{"f47ac10b-58cc-4372-a567-0e02b2c3d479", "2025-06-15T13:15:00Z", "A"},

			// MPXN 2: 6ba7b810-9dad-41d1-80b4-00c04fd430c8 (6 readings)
			{"6ba7b810-9dad-41d1-80b4-00c04fd430c8", "2025-01-20T10:15:00Z", "E"},
			{"6ba7b810-9dad-41d1-80b4-00c04fd430c8", "2025-02-20T11:30:00Z", "E"},
			{"6ba7b810-9dad-41d1-80b4-00c04fd430c8", "2025-03-20T12:45:00Z", "E"},
			{"6ba7b810-9dad-41d1-80b4-00c04fd430c8", "2025-04-20T14:00:00Z", "E"},
			{"6ba7b810-9dad-41d1-80b4-00c04fd430c8", "2025-05-20T15:15:00Z", "E"},
			{"6ba7b810-9dad-41d1-80b4-00c04fd430c8", "2025-06-20T16:30:00Z", "E"},

			// MPXN 3: 550e8400-e29b-41d4-a716-446655440000 (6 readings)
			{"550e8400-e29b-41d4-a716-446655440000", "2025-02-05T14:20:00Z", "A"},
			{"550e8400-e29b-41d4-a716-446655440000", "2025-03-05T15:35:00Z", "A"},
			{"550e8400-e29b-41d4-a716-446655440000", "2025-04-05T16:50:00Z", "A"},
			{"550e8400-e29b-41d4-a716-446655440000", "2025-05-05T08:05:00Z", "A"},
			{"550e8400-e29b-41d4-a716-446655440000", "2025-06-05T09:20:00Z", "A"},
			{"550e8400-e29b-41d4-a716-446655440000", "2025-07-05T10:35:00Z", "A"},
		}

		for _, reading := range readings {
			err := dynamodbhelper.Save(ctx, client, Reading{
				MPXN:  reading.mpxn,
				TS:    reading.ts,
				Value: fmt.Sprintf("%.16f", rand.Float64()),
				Type:  reading.typ,
			})
			if err != nil {
				l.ErrorContext(ctx, "failed to save reading to dynamodb", slog.String("error", err.Error()))
				return
			}
		}

		l.InfoContext(ctx, "saved data to dynamodb")
	}
}
