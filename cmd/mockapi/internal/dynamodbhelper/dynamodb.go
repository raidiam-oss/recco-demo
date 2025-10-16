package dynamodbhelper

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// Pointer returns a pointer to the input value of a comparable type T. The returned pointer can be used to access or modify the original value.
func Pointer[T comparable](v T) *T {
	return &v
}

type Item interface {
	TableName() string
	PrimaryIndex() string
}

func Get[T Item](ctx context.Context, client *dynamodb.Client, indexValue string, item T) error {
	indexValueAttribute, err := attributevalue.Marshal(indexValue)
	if err != nil {
		return fmt.Errorf("error parsing provided index value as an attribute: %w", err)
	}

	queryOutput, err := client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: Pointer(item.TableName()),
		Key: map[string]types.AttributeValue{
			item.PrimaryIndex(): indexValueAttribute,
		},
	})
	if err != nil {
		return fmt.Errorf("error querying dynamodb: %w", err)
	}

	err = attributevalue.UnmarshalMap(queryOutput.Item, &item)
	if err != nil {
		return fmt.Errorf("error unmarshalling query response: %w", err)
	}

	return nil
}

func Save[T Item](ctx context.Context, client *dynamodb.Client, item T) error {
	dataBytes, err := json.Marshal(item)
	if err != nil {
		return fmt.Errorf("error marshalling provided item to json: %w", err)
	}
	dataMap := &map[string]any{}
	err = json.Unmarshal(dataBytes, dataMap)
	if err != nil {
		return fmt.Errorf("error converting marshalled item to a map: %w", err)
	}

	itemAttributes, err := attributevalue.MarshalMap(dataMap)
	if err != nil {
		return fmt.Errorf("error marshalling map to dynamodb attributes: %w", err)
	}

	_, err = client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(item.TableName()),
		Item:      itemAttributes,
	})
	if err != nil {
		return fmt.Errorf("error writing item to dynamo: %w", err)
	}
	return nil
}
