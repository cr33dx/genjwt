package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load(".env")

	if err != nil {
		fmt.Println("Error loading .env file", err)
	}

	alg := flag.String("alg", "HS_256", "algo to sign token")
	env := flag.String("env", "qa", "environment to use")
	roles := flag.String("roles", "SUPER_ADMIN,ADMIN", "roles to attach")
	aud := flag.String("aud", "api://default", "audiance")
	validity := flag.Uint("validity", 4, "validity in hours")
	client_id := flag.String("client_id", "cid", "client id")
	partner_id := flag.String("pid", "1eb44052-6880-4d7e-9e5a-3a8fbf7d2929", "partner id")
	flag.Parse()
	var key string
	switch *env {
	case "qa":
		key = os.Getenv("QA_JWT_KEY")
	case "stg":
		key = os.Getenv("STG_JWT_KEY")
	default:
		fmt.Printf("env not supported")
		return
	}
	var algo_to_be_used jwt.SigningMethod
	switch *alg {
	case "HS_256":
		algo_to_be_used = jwt.SigningMethodHS256
	default:
		fmt.Printf("alg not supported")
		return
	}

	type CustomClaims struct {
		Roles      []string `json:"roles"`
		Client_id  string   `json:"cid"`
		Audience   string   `json:"aud"`
		Partner_id string   `json:"partner_id"`
		jwt.RegisteredClaims
	}

	claims := CustomClaims{
		strings.Split(*roles, ","),
		*client_id,
		*aud,
		*partner_id,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(*validity) * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(algo_to_be_used, claims)
	ss, err := token.SignedString([]byte(key))
	if err != nil {
		fmt.Println("error is", err)
	}
	fmt.Println(ss)
}
