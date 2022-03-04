package main

import (
	"fmt"
	"jwt-test/token"
	"log"
	"time"
)

func main() {
	// init the jwt key
	token.InitKey("1145141919810")

	// create a token
	normalToken, err := token.ReleaseToken(1, "Teacher", time.Hour, 0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Normal Token:\n", normalToken)
	// parse the token
	parseToken(normalToken)

	// create a token that expires in 1 second
	expiredToken, err := token.ReleaseToken(2, "Student", time.Second, 0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Expired Token:\n", expiredToken)
	// Wait 2 second and make sure the token is expired
	fmt.Println("Wait 2 second...")
	time.Sleep(time.Second * 2)
	// try to parse it
	parseToken(expiredToken)

	// create a token that not before 1 minutes
	notBeforeToken, err := token.ReleaseToken(3, "Admin", time.Hour, time.Minute)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Not Before Token:\n", notBeforeToken)
	// try to parse it
	parseToken(notBeforeToken)
}

// parseToken parse token string and print info in it
func parseToken(tokenString string) {
	// try to parse token
	parsedToken, claims, err := token.ParseToken(tokenString)
	if err != nil {
		log.Println(err)
	}
	// print parsed data
	fmt.Println("Parse Token:\n", parsedToken)
	valiedStatus := parsedToken.Valid
	fmt.Println("Token Valied Status:\n", valiedStatus)
	fmt.Println("Parse Claims:\n", claims)
	userID := claims.UserID
	identify := claims.Identify
	fmt.Println("UserID:\n", userID)
	fmt.Println("Identify:\n", identify)
	expireAt := claims.ExpiresAt.Local().Format("2006-01-02 15:04:05")
	issueAt := claims.IssuedAt.Local().Format("2006-01-02 15:04:05")
	notBefore := claims.NotBefore.Local().Format("2006-01-02 15:04:05")
	fmt.Println("ExpiresAt:\n", expireAt)
	fmt.Println("IssuedAt:\n", issueAt)
	fmt.Println("NotBefore:\n", notBefore)
}
