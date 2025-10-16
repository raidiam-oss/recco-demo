package api

type Energy struct {
	ID         string `json:"id" dynamodbav:"id"`
	CustomerId string `json:"customer_id" dynamodbav:"customer_id"`
	EnergyType string `json:"energy_type" dynamodbav:"energy_type"`
	Price      string `json:"price" dynamodbav:"price"`
	Date       string `json:"date" dynamodbav:"date"`
}

func (e Energy) TableName() string {
	return "energy"
}

func (e Energy) PrimaryIndex() string {
	return "id"
}

type Customer struct {
	ID        string `json:"id" dynamodbav:"id"`
	FirstName string `json:"first_name" dynamodbav:"first_name"`
	LastName  string `json:"last_name" dynamodbav:"last_name"`
	DOB       string `json:"dob" dynamodbav:"dob"`
	Address   string `json:"address" dynamodbav:"address"`
}

func (c Customer) TableName() string {
	return "customers"
}

func (c Customer) PrimaryIndex() string {
	return "id"
}
