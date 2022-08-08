package main

import (
	"bufio"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"log"
	"net/mail"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/dcu/go-authy"
	"github.com/go-redis/redis/v8"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	jwtware "github.com/gofiber/jwt/v3"
	"github.com/golang-jwt/jwt/v4"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	gomail "gopkg.in/mail.v2"
)

var (
	ReactBuildPath = "../frontend/build/"
	ctx            = context.Background()
	RedisClient    = redis.NewClient(&redis.Options{
		Addr:     "redis-13070.c60.us-west-1-2.ec2.cloud.redislabs.com:13070",
		Password: "hMdvLWMi7QhVwi2GafiCAqDAAm7UKVr7",
		DB:       0,
	})
	privateKey     *rsa.PrivateKey
	publicKey      crypto.PublicKey
	PostgresClient *sql.DB
)

func AuthRequired(allowedRoles []string) func(*fiber.Ctx) error {
	return jwtware.New(jwtware.Config{
		SigningKey:    publicKey,
		SigningMethod: jwtware.RS256,
		ContextKey:    "user",
		TokenLookup:   "cookie:user",
		SuccessHandler: func(c *fiber.Ctx) error {
			user := c.Locals("user").(*jwt.Token)
			claims := user.Claims.(jwt.MapClaims)
			role := claims["role"].(string)
			println("role:", role)

			if !VerifyRole(role, allowedRoles) {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error":   true,
					"message": "User is not privileged",
				})
			}

			return c.Next()
		},
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if err.Error() == "Missing or malformed JWT" {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err.Error(),
				})
			}

			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   true,
				"message": err.Error(),
			})
		},
	})
}

func InitAuthy() *authy.Authy {
	return authy.NewAuthyAPI("TrDpQWDFZ3hklrW7gRQkEzzNMTwQ8RDF")
}

func VerifyRole(userRole string, allowedRoles []string) bool {
	for i := 0; i < len(allowedRoles); i++ {
		if userRole == allowedRoles[i] {
			return true
		}
	}

	return false
}

func SetPrivateAndPublicKey() error {
	privateKeyFile, err := os.Open("./jwt.pem")
	if err != nil {
		return err
	}

	pemfileinfo, _ := privateKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(privateKeyFile)
	_, err = buffer.Read(pembytes)
	if err != nil {
		return err
	}

	data, _ := pem.Decode([]byte(pembytes))
	privateKeyFile.Close()

	privateKeyImported, err := x509.ParsePKCS1PrivateKey(data.Bytes)
	if err != nil {
		return err
	}

	privateKey = privateKeyImported
	publicKey = privateKeyImported.Public()
	return nil
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func ValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func ValidPhoneNumber(phoneNumber string) bool {
	expression := regexp.MustCompile(``)
	return expression.MatchString(phoneNumber)
}

func NilOnEmptyString(s string) interface{} {
	if len(s) == 0 {
		return nil
	}
	return s
}

func SendEmailToken(baseUrl, email, token string) error {
	hostEmail := "austin.yono@gmail.com"
	tokenLink := baseUrl + "/api/authenticate/email/" + token

	mail := gomail.NewMessage()
	mail.SetHeader("From", hostEmail)
	mail.SetHeader("To", email)
	mail.SetHeader("Subject", "Golang Email Verification")
	mail.SetBody("text/plain", tokenLink)

	dialer := gomail.NewDialer("smtp.gmail.com", 587, hostEmail, gmailAppKey)
	dialer.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	return dialer.DialAndSend(mail)
}

func PostRegister(c *fiber.Ctx) error {
	type LoginInfo struct {
		FirstName   string
		LastName    string
		Email       string
		CountryCode int
		PhoneNumber string
		Password    string
	}

	loginInfo := LoginInfo{}

	if err := c.BodyParser(&loginInfo); err != nil {
		return err
	}

	validEmail := ValidEmail(loginInfo.Email)
	if (!validEmail && (loginInfo.CountryCode == 0 || loginInfo.PhoneNumber == "")) || loginInfo.FirstName == "" || loginInfo.LastName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid request",
		})
	}

	println("ip", url.Values{"ip": {}}, c.IP())
	println(loginInfo.Email)
	println(loginInfo.PhoneNumber)
	println(loginInfo.Password)

	checkForExistingUserQuery := "SELECT ID FROM USERS WHERE "
	if validEmail {
		checkForExistingUserQuery += "Email = $1 "
	}
	if validEmail && loginInfo.PhoneNumber != "" {
		checkForExistingUserQuery += " OR "
	}
	if loginInfo.PhoneNumber != "" {
		if !validEmail {
			checkForExistingUserQuery += "PhoneNumber = $1"
		} else {
			checkForExistingUserQuery += "PhoneNumber = $2"
		}
	}
	checkForExistingUserQuery += " LIMIT 1"

	var rows *sql.Rows
	var err error
	if validEmail && loginInfo.PhoneNumber != "" {
		rows, err = PostgresClient.Query(checkForExistingUserQuery, loginInfo.Email, loginInfo.PhoneNumber)
	} else if validEmail {
		rows, err = PostgresClient.Query(checkForExistingUserQuery, loginInfo.Email)
	} else {
		rows, err = PostgresClient.Query(checkForExistingUserQuery, loginInfo.PhoneNumber)
	}

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": err.Error(),
		})
	}
	defer rows.Close()

	if rows.Next() {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   true,
			"message": "User already exists",
		})
	}

	hashedPassword, err := HashPassword(loginInfo.Password)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": err.Error(),
		})
	}

	var emailToken string
	if validEmail {
		hash, err := bcrypt.GenerateFromPassword([]byte(loginInfo.Email), bcrypt.MinCost)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error":   true,
				"message": err.Error(),
			})
		}

		emailToken = base64.StdEncoding.EncodeToString(hash)
	}

	_, err = PostgresClient.Exec(`INSERT INTO USERS(ID, FirstName, LastName, Email, EmailChangeToken, EmailChangeTimestamp, PhoneNumber, Password)
	VALUES(uuid_generate_v4(), $1, $2, $3, $4, $5, $6, $7)
	`, loginInfo.FirstName, loginInfo.LastName, NilOnEmptyString(loginInfo.Email), NilOnEmptyString(emailToken), time.Now().UTC(), NilOnEmptyString(loginInfo.PhoneNumber), hashedPassword)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": err.Error(),
		})
	}

	if validEmail {
		err = SendEmailToken(c.BaseURL(), loginInfo.Email, emailToken)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error":   true,
				"message": err.Error(),
			})
		}
	}

	// Authy := InitAuthy()
	// verificationStart, err := Authy.StartPhoneVerification(loginInfo.CountryCode, loginInfo.PhoneNumber, "sms", url.Values{"ip": {c.IP()}})
	// if err != nil {
	// 	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
	// 		"error":   true,
	// 		"message": "Invalid request",
	// 	})
	// }

	// user, err := Authy.RegisterUser(loginInfo.Email, loginInfo.CountryCode, loginInfo.PhoneNumber, url.Values{"ip": {c.IP()}})
	// if err != nil {
	// 	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
	// 		"error":   true,
	// 		"message": err.Error(),
	// 	})
	// }

	return c.JSON(fiber.Map{"status": true})
}

func PostAuthenticate(c *fiber.Ctx) error {
	type LoginInfo struct {
		Email       string
		CountryCode int
		PhoneNumber string
		Password    string
	}

	loginInfo := LoginInfo{}

	if err := c.BodyParser(&loginInfo); err != nil {
		return err
	}

	validEmail := ValidEmail(loginInfo.Email)
	if loginInfo.Email != "" && loginInfo.PhoneNumber != "" && !validEmail && (loginInfo.CountryCode == 0 || loginInfo.PhoneNumber == "") {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid request",
		})
	}

	checkForExistingUserQuery := `SELECT
		ID, Email, PhoneNumber, Password, Roles,
		EmailVerified, PhoneNumberVerified, AuthorizedIPAddresses, LoginEmailRequired, LoginTextMessageRequired,
		Banned, BannedUntil
		FROM USERS WHERE `
	if loginInfo.Email != "" {
		checkForExistingUserQuery += `Email = '` + loginInfo.Email + `'`
	} else if loginInfo.PhoneNumber != "" {
		checkForExistingUserQuery += `PhoneNumber = '` + loginInfo.PhoneNumber + `'`
	}
	checkForExistingUserQuery += ` LIMIT 1`
	rows, err := PostgresClient.Query(checkForExistingUserQuery)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": err.Error(),
		})
	}
	defer rows.Close()
	if !rows.Next() {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "User does not exist",
		})
	}

	type AccountInfo struct {
		ID                       string
		Email                    sql.NullString
		PhoneNumber              sql.NullString
		Password                 string
		Roles                    []sql.NullString
		EmailVerified            bool
		PhoneNumberVerified      bool
		AuthorizedIPAddresses    []sql.NullString
		LoginEmailRequired       bool
		LoginTextMessageRequired bool
		Banned                   bool
		BannedUntil              sql.NullTime
	}
	accountInfo := AccountInfo{}
	err = rows.Scan(&accountInfo.ID, &accountInfo.Email, &accountInfo.PhoneNumber, &accountInfo.Password,
		pq.Array(&accountInfo.Roles), &accountInfo.EmailVerified, &accountInfo.PhoneNumberVerified, pq.Array(&accountInfo.AuthorizedIPAddresses),
		&accountInfo.LoginEmailRequired, &accountInfo.LoginTextMessageRequired, &accountInfo.Banned, &accountInfo.BannedUntil)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": err.Error(),
		})
	}

	authenticated := CheckPasswordHash(loginInfo.Password, accountInfo.Password)
	if !authenticated {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid password",
		})
	}

	// Create the Claims
	var claims jwt.MapClaims
	expireTime := time.Now().Add(time.Minute * 5)

	if accountInfo.LoginEmailRequired {
		// Send back uuid to user
		// Send user an email or text message
		// if email -> "email auth sent"
		// if text message -> "enter authorization code"
		claims = jwt.MapClaims{
			"uuid":                     accountInfo.ID,
			"emailAuthenticated":       false,
			"phoneNumberAuthenticated": !accountInfo.LoginTextMessageRequired,
			"exp":                      expireTime.Unix(),
		}
	} else if accountInfo.LoginTextMessageRequired {
		claims = jwt.MapClaims{
			"uuid":                     accountInfo.ID,
			"emailAuthenticated":       true,
			"phoneNumberAuthenticated": false,
			"exp":                      expireTime.Unix(),
		}
	} else {
		claims = jwt.MapClaims{
			"uuid":                     accountInfo.ID,
			"emailAuthenticated":       false,
			"phoneNumberAuthenticated": false,
			"exp":                      expireTime.Unix(),
		}
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Generate encoded token and send it as response.
	jwt, err := token.SignedString(privateKey)
	if err != nil {
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	c.Cookie(&fiber.Cookie{
		Name:     "user",
		HTTPOnly: true,
		// Secure: true,
		// SameSite: "ethiono.com",
		Value:   jwt,
		Expires: expireTime,
	})

	if !accountInfo.LoginEmailRequired && !accountInfo.LoginTextMessageRequired {
		errorMessage := "You must verify your "
		if accountInfo.Email.Valid && ValidEmail(accountInfo.Email.String) {
			// TODO: resend email if last sent email is older than 5 min
			errorMessage += "email"
		} else {
			// TODO: resend email if last sent text message is older than 5 min
			errorMessage += "phone number"
		}

		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   false,
			"message": errorMessage,
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error": false,
	})
}

func PostAuthenticateEmail(c *fiber.Ctx) error {
	token := c.Params("token")
	if token == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   true,
			"message": "No token",
		})
	}

	rows, err := PostgresClient.Query("SELECT Id, Email, EmailChangeTimestamp FROM USERS WHERE EmailChangeToken = $1", token)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": err.Error(),
		})
	}
	defer rows.Close()

	if !rows.Next() {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Token is not valid",
		})
	}

	type AccountInfo struct {
		ID                   string
		Email                sql.NullString
		EmailChangeTimestamp sql.NullTime
	}
	accountInfo := AccountInfo{}
	err = rows.Scan(&accountInfo.ID, &accountInfo.Email, &accountInfo.EmailChangeTimestamp)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": err.Error(),
		})
	}

	if !accountInfo.EmailChangeTimestamp.Valid {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Timestamp Invalid",
		})
	}

	allowedTimePeriod := time.Now().In(accountInfo.EmailChangeTimestamp.Time.Location()).Add(-time.Minute * 10) // 5 minutes

	if !accountInfo.EmailChangeTimestamp.Time.After(allowedTimePeriod) || !accountInfo.EmailChangeTimestamp.Time.Before(time.Now().In(accountInfo.EmailChangeTimestamp.Time.Location())) {
		if !accountInfo.Email.Valid {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error":   true,
				"message": "Invalid Email",
			})
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(accountInfo.Email.String), bcrypt.MinCost)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error":   true,
				"message": err.Error(),
			})
		}

		emailToken := base64.StdEncoding.EncodeToString(hash)

		_, err = PostgresClient.Exec(`UPDATE USERS
		SET EmailChangeToken = $1 , EmailChangeTimestamp = $2
		WHERE Id = $3
		`, emailToken, time.Now().UTC(), accountInfo.ID)

		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error":   true,
				"message": err.Error(),
			})
		}

		println("new token generated")
		println("old", token)
		println("new email token", emailToken)

		err = SendEmailToken(c.BaseURL(), accountInfo.Email.String, emailToken)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error":   true,
				"message": err.Error(),
			})
		}

		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Token expired",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error": false,
	})
}

func GetRefresh(c *fiber.Ctx) error {
	return c.SendString("Need to setup refresh token")
}

func ConfigureCors() func(*fiber.Ctx) error {
	return cors.New(cors.Config{
		AllowOrigins: "https://ethiono.com",
		AllowHeaders: "Origin, Content-Type, Accept",
	})
}

func SendIndexHTML(c *fiber.Ctx) error {
	return c.SendFile(ReactBuildPath + "index.html")
}

func HandleDefaultRoutes(c *fiber.Ctx) error {
	// If it's an API route
	if strings.HasPrefix(c.Path(), "/api") {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid route",
		})
	}

	// If the request method is not GET
	if c.Method() != "GET" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid request",
		})
	}

	// If the file exists in the frontend build directory
	if _, err := os.Stat(ReactBuildPath + c.Path()); !os.IsNotExist(err) {
		return c.SendFile(ReactBuildPath + c.Path())
	}

	// Otherwise return React's index html
	return SendIndexHTML(c)
}

// err := RedisClient.Set(ctx, "oqipoei", "hello dude1", 0).Err()
// if err != nil {
// 	panic(err)
// }

// result, err := RedisClient.Get(ctx, "key").Result()
// if err != nil {
// 	panic(err)
// }
// print(result)

func DropUsersTable() {
	exec, err := PostgresClient.Prepare(`DROP TABLE IF EXISTS USERS`)
	if err != nil {
		panic(err)
	}
	_, err = exec.Exec()
	if err != nil {
		panic(err)
	}
}

func CreateUsersTable() {
	exec, err := PostgresClient.Prepare(`CREATE TABLE IF NOT EXISTS USERS (
		ID UUID PRIMARY KEY,
		FirstName TEXT NOT NULL,
		LastName TEXT NOT NULL,
		Email TEXT UNIQUE,
		PhoneNumber TEXT UNIQUE,
		Password TEXT,
		LastSignIn TIMESTAMP,
		EmailVerified BOOLEAN DEFAULT FALSE NOT NULL,
		PhoneNumberVerified BOOLEAN DEFAULT FALSE NOT NULL,
		AuthorizedIPAddresses CIDR[],
		LoginEmailRequired BOOLEAN DEFAULT FALSE NOT NULL,
		LoginEmailToken TEXT,
		LoginTextMessageRequired BOOLEAN DEFAULT FALSE NOT NULL,
		LoginTextMessageToken TEXT,
		Roles TEXT[],
		EmailConfirmedTimestamp TIMESTAMP,
		PhoneNumberConfirmedTimestamp TIMESTAMP,
		RecoveryToken TEXT,
		RecoveryTimestamp TIMESTAMP,
		EmailChangeToken TEXT,
		EmailChangeTimestamp TIMESTAMP,
		PhoneNumberChangeToken TEXT,
		PhoneNumberChangeTimestamp TIMESTAMP,
		Banned BOOLEAN DEFAULT FALSE NOT NULL,
		BannedUntil TIMESTAMP,
		CONSTRAINT EmailOrPhoneNumberNotNull CHECK (
			NOT (
				(Email IS NULL OR EMAIL = '')
				AND
				(PhoneNumber IS NULL OR PhoneNumber = '')
			)
		),
		CONSTRAINT NoEmailRequired CHECK (
			NOT (
				(Email IS NULL OR EMAIL = '')
				AND
				(LoginEmailRequired IS TRUE)
			)
		),
		CONSTRAINT NoTextRequired CHECK (
			NOT (
				(PhoneNumber IS NULL OR PhoneNumber = '')
				AND
				(LoginTextMessageRequired IS TRUE)
			)
		),
		CONSTRAINT BannedUntilNotNull CHECK (
			NOT (
				(Banned IS TRUE)
				AND
				(BannedUntil IS NULL)
			)
		)
	 );`)
	if err != nil {
		panic(err)
	}
	_, err = exec.Exec()
	if err != nil {
		panic(err)
	}
}

func InsertUsersTable() {
	exec, err := PostgresClient.Prepare(`INSERT INTO USERS(ID, FirstName, LastName, Email, Password, Roles)
	VALUES(uuid_generate_v4(), 'Austin', 'Yono', 'austin.yono@gmail.com', 'Ay230203', ARRAY ['Admin', 'Employee', 'Customer'])
	`)
	if err != nil {
		panic(err)
	}
	_, err = exec.Exec()
	if err != nil {
		panic(err)
	}
}

func PrintUsersTable() {
	exec, err := PostgresClient.Prepare(`SELECT Email FROM USERS WHERE FirstName = 'Austin' LIMIT 1`)
	if err != nil {
		panic(err)
	}
	rows, err := exec.Query()
	if err != nil {
		panic(err)
	}
	defer rows.Close()
	for rows.Next() {
		var result string
		if err := rows.Scan(&result); err != nil {
			log.Fatal(err)
		}
		print(result)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}
}

func InitPostgres() error {
	PostgresTemp, err := sql.Open("postgres", "host=db-postgresql-nyc3-12531-do-user-11708997-0.b.db.ondigitalocean.com port=25060 user=doadmin dbname=defaultdb sslmode=require password=AVNS_JGa52SCc3OQiIHD")
	if err != nil {
		return err
	}
	err = PostgresTemp.Ping()
	if err != nil {
		return err
	}
	PostgresClient = PostgresTemp
	return nil
}

func main() {
	defer RedisClient.Close()

	err := InitPostgres()
	if err != nil {
		panic(err)
	}
	defer PostgresClient.Close()

	// DropUsersTable()
	// CreateUsersTable()

	// InsertUsersTable()
	PrintUsersTable()

	err = SetPrivateAndPublicKey()
	if err != nil {
		panic(err)
	}

	// Routing
	MainRouter := fiber.New(fiber.Config{
		EnableTrustedProxyCheck: true,
	})
	APIRouter := MainRouter.Group("/api")

	MainRouter.Use(ConfigureCors())
	APIRouter.Use(ConfigureCors())

	APIRouter.Post("/register", PostRegister)
	APIRouter.Post("/register/email", PostRegister)
	APIRouter.Post("/authenticate", PostAuthenticate)
	APIRouter.Get("/authenticate/email/:token", PostAuthenticateEmail)
	APIRouter.Post("/authenticate/text-message", PostAuthenticate)
	APIRouter.Get("/refresh", GetRefresh)

	MainRouter.Get("/admin/dashboard", AuthRequired([]string{"Admin"}), SendIndexHTML)
	MainRouter.Get("/dashboard", AuthRequired([]string{"Admin", "Employee", "Customer"}), SendIndexHTML)
	MainRouter.Use(HandleDefaultRoutes)

	log.Fatal(MainRouter.Listen(":3000"))
}
