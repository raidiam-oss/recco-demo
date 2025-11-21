package dynamodbhelper

import (
	"context"
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
	itemAttributes, err := attributevalue.MarshalMap(item)
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

// QueryByDateRange queries items with a composite key (partition key + sort key range)
func QueryByDateRange(ctx context.Context, client *dynamodb.Client, tableName, partitionKey, partitionValue, sortKey, startDate, endDate string, result interface{}) error {
	partitionValueAttr, err := attributevalue.Marshal(partitionValue)
	if err != nil {
		return fmt.Errorf("error marshalling partition value: %w", err)
	}

	startDateAttr, err := attributevalue.Marshal(startDate)
	if err != nil {
		return fmt.Errorf("error marshalling start date: %w", err)
	}

	endDateAttr, err := attributevalue.Marshal(endDate)
	if err != nil {
		return fmt.Errorf("error marshalling end date: %w", err)
	}

	input := &dynamodb.QueryInput{
		TableName:              Pointer(tableName),
		KeyConditionExpression: Pointer(fmt.Sprintf("%s = :pkval AND %s BETWEEN :start AND :end", partitionKey, sortKey)),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pkval": partitionValueAttr,
			":start": startDateAttr,
			":end":   endDateAttr,
		},
	}

	output, err := client.Query(ctx, input)
	if err != nil {
		return fmt.Errorf("error querying dynamodb: %w", err)
	}

	if len(output.Items) == 0 {
		return nil // No items found
	}

	err = attributevalue.UnmarshalListOfMaps(output.Items, result)
	if err != nil {
		return fmt.Errorf("error unmarshalling query results: %w", err)
	}

	return nil
}

// DeleteAll deletes all items from the specified DynamoDB table
// This performs a scan and batch delete operation
//
//nolint:staticcheck
func DeleteAll(ctx context.Context, client *dynamodb.Client, tableName string) error {
	// First, describe the table to get key schema
	describeOutput, err := client.DescribeTable(ctx, &dynamodb.DescribeTableInput{
		TableName: Pointer(tableName),
	})
	if err != nil {
		return fmt.Errorf("error describing table: %w", err)
	}

	// Extract key attribute names
	var hashKey, rangeKey string
	for _, key := range describeOutput.Table.KeySchema {
		if key.KeyType == types.KeyTypeHash {
			hashKey = *key.AttributeName
		} else if key.KeyType == types.KeyTypeRange {
			rangeKey = *key.AttributeName
		}
	}

	if hashKey == "" {
		return fmt.Errorf("no hash key found for table %s", tableName)
	}

	// Scan the table to get all items
	scanPaginator := dynamodb.NewScanPaginator(client, &dynamodb.ScanInput{
		TableName: Pointer(tableName),
	})

	var totalDeleted int
	for scanPaginator.HasMorePages() {
		page, err := scanPaginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("error scanning table: %w", err)
		}

		if len(page.Items) == 0 {
			continue
		}

		// Build batch delete requests (max 25 items per batch)
		for i := 0; i < len(page.Items); i += 25 {
			end := i + 25
			if end > len(page.Items) {
				end = len(page.Items)
			}

			batch := page.Items[i:end]
			writeRequests := make([]types.WriteRequest, 0, len(batch))

			for _, item := range batch {
				key := make(map[string]types.AttributeValue)
				key[hashKey] = item[hashKey]
				if rangeKey != "" {
					key[rangeKey] = item[rangeKey]
				}

				writeRequests = append(writeRequests, types.WriteRequest{
					DeleteRequest: &types.DeleteRequest{
						Key: key,
					},
				})
			}

			// Execute batch delete
			_, err := client.BatchWriteItem(ctx, &dynamodb.BatchWriteItemInput{
				RequestItems: map[string][]types.WriteRequest{
					tableName: writeRequests,
				},
			})
			if err != nil {
				return fmt.Errorf("error batch deleting items: %w", err)
			}

			totalDeleted += len(writeRequests)
		}
	}

	return nil
}
