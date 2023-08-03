package main

import (
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"log"
	"net/http"
	"fmt"
	"crypto/rand"
	"encoding/hex"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"io/ioutil"
	"net/url"
	"math/big"
	"crypto/elliptic"
	"github.com/pelicanplatform/pelican/config"
	"database/sql"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

type Namespace struct {
	ID            int
	Prefix        string
	Pubkey        string
	Identity      string
	AdminMetadata string
}

func createNamespaceTable(db *sql.DB) {
	query := `
    CREATE TABLE IF NOT EXISTS namespace (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        prefix TEXT NOT NULL UNIQUE,
        pubkey TEXT NOT NULL,
        identity TEXT,
        admin_metadata TEXT
    );`

	_, err := db.Exec(query)
	if err != nil {
		log.Fatalf("Failed to create table: %v", err)
	}
}

func addNamespace(db *sql.DB, ns *Namespace) error {
	query := `INSERT INTO namespace (prefix, pubkey, identity, admin_metadata) VALUES (?, ?, ?, ?)`
	_, err := db.Exec(query, ns.Prefix, ns.Pubkey, ns.Identity, ns.AdminMetadata)
	return err
}

func updateNamespace(db *sql.DB, ns *Namespace) error {
	query := `UPDATE namespace SET pubkey = ?, identity = ?, admin_metadata = ? WHERE prefix = ?`
	_, err := db.Exec(query, ns.Pubkey, ns.Identity, ns.AdminMetadata, ns.Prefix)
	return err
}

func deleteNamespace(db *sql.DB, prefix string) error {
	query := `DELETE FROM namespace WHERE prefix = ?`
	_, err := db.Exec(query, prefix)
	return err
}

func getNamespace(db *sql.DB, prefix string) (*Namespace, error) {
	ns := &Namespace{}
	query := `SELECT * FROM namespace WHERE prefix = ?`
	err := db.QueryRow(query, prefix).Scan(&ns.ID, &ns.Prefix, &ns.Pubkey, &ns.Identity, &ns.AdminMetadata)
	if err != nil {
		return nil, err
	}
	return ns, nil
}

func getAllNamespaces(db *sql.DB) ([]*Namespace, error) {
	query := `SELECT * FROM namespace`
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	namespaces := make([]*Namespace, 0)
	for rows.Next() {
		ns := &Namespace{}
		if err := rows.Scan(&ns.ID, &ns.Prefix, &ns.Pubkey, &ns.Identity, &ns.AdminMetadata); err != nil {
			return nil, err
		}
		namespaces = append(namespaces, ns)
	}

	return namespaces, nil
}

func InitDB() (*sql.DB){

	db, err := sql.Open("sqlite3", "./namespace.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	createNamespaceTable(db)

	return db
}


var (
	OIDCClientID        string = "cilogon:/client_id/385a98bfe7c6c5699ee5da7ccdb37157"
	OIDCClientSecret    string = "G79dobp9BVoMBr3a2gmz7s0IiTaBj_vNANXWI2rwP-PT64q6Na-pN3_uUJfWe7svBkJApQxpVxlASHaP6Qyd7w"
	OIDCScope           string = "openid profile email org.cilogon.userinfo"
	DeviceAuthEndpoint  string = "https://cilogon.org/oauth2/device_authorization"
	TokenEndpoint       string = "https://cilogon.org/oauth2/token"
	GrantType           string = "urn:ietf:params:oauth:grant-type:device_code"
)

var db *sql.DB

type Response struct {
	VerificationURLComplete string `json:"verification_uri_complete"`
	DeviceCode             string `json:"device_code"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
}

func main() {
	db = InitDB()
	_ = godotenv.Load()

	router := gin.Default()

	router.POST("/cli-namespaces/registry", cliRegisterNamespace)
	router.GET("/cli-namespaces", dbGetAllNamespaces)
	router.DELETE("/cli-namespaces/:prefix", dbDeleteNamespace)
	router.GET("/cli-namespaces/:prefix/issuer.jwks", getJwks)
	router.GET("/cli-namespaces/:prefix/.well-known/openid-configuration", getOpenIDConfiguration)

	log.Fatal(router.Run(":8080"))
}

func keySignChallenge(c *gin.Context, data map[string]interface{}, action string) {
	_, cnOk := data["client_nonce"].(string)
	_, cpdOk := data["client_payload"].(string)
	_, csOk := data["client_signature"].(string)

	_, snOk := data["server_nonce"].(string)
	_, spOk := data["server_payload"].(string)
	_, ssOk := data["server_signature"].(string)

	_, cpOk := data["pubkey"].(map[string]interface{})

	if cnOk && snOk && cpOk && cpdOk && csOk && spOk && ssOk {
		fmt.Println("Key Sign Challenge Commit")
		keySignChallengeCommit(c, data, action)
	} else if cnOk {
		fmt.Println("Key Sign Challenge Init")
		keySignChallengeInit(c, data)
	} else {
		fmt.Println("Missing Parameters")
		c.JSON(http.StatusMultipleChoices, gin.H{"status": "MISSING PARAMETERS"})
	}
}

// The same as pelican/cmd/namespace_registry.go:generateNonce
func generateNonce() (string, error) {
    nonce := make([]byte, 32)
    _, err := rand.Read(nonce)
    if err != nil {
        return "", err
    }
    return hex.EncodeToString(nonce), nil
}

func signPayload(payload []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
    hash := sha256.Sum256(payload)
    signature, err := privateKey.Sign(rand.Reader, hash[:], crypto.SHA256)  // Use crypto.SHA256 instead of the hash[:]
    if err != nil {
        return nil, err
    }
    return signature, nil
}

func verifySignature(payload []byte, signature []byte, publicKey *ecdsa.PublicKey) bool {
	hash := sha256.Sum256(payload)
	return ecdsa.VerifyASN1(publicKey, hash[:], signature)
}

func keySignChallengeInit(c *gin.Context, data map[string]interface{}) {
    clientNonce, _ := data["client_nonce"].(string)
	serverNonce, err := generateNonce()
	if err != nil {
		fmt.Println("Error generating nonce")
	}

    serverPayload := []byte(clientNonce + serverNonce)
	_, err = config.LoadPublicKey("", "/app/key/server.key")
	if err != nil {
		fmt.Println("err" + err.Error())
	}

    privateKey, err := config.LoadPrivateKey("/app/key/server.key")
	if err != nil {
		fmt.Println("Error loading private key")
	} 

    serverSignature, _ := signPayload(serverPayload, privateKey)
    c.JSON(http.StatusOK, gin.H{
        "server_nonce": serverNonce,
        "client_nonce": clientNonce,
        "server_payload": hex.EncodeToString(serverPayload),
        "server_signature": hex.EncodeToString(serverSignature),
    })

}

func jwksToEcdsaPublicKey(jwks map[string]interface{}) *ecdsa.PublicKey {
	x := jwks["x"].(string)
	y := jwks["y"].(string)
	xBigInt, _ := new(big.Int).SetString(x, 10)
	yBigInt, _ := new(big.Int).SetString(y, 10)

	clientPubkey := &ecdsa.PublicKey{
		Curve: elliptic.P521(),
		X:     xBigInt,
		Y:     yBigInt,
	}

	return clientPubkey
}	

func keySignChallengeCommit(c *gin.Context, data map[string]interface{}, action string) {
    clientNonce, _ := data["client_nonce"].(string)
    serverNonce, _ := data["server_nonce"].(string)
    jsonPublicKey := data["pubkey"].(map[string]interface{})

	clientPubkey := jwksToEcdsaPublicKey(jsonPublicKey)
	clientPayload := []byte(clientNonce + serverNonce)
    clientSignature, _ := hex.DecodeString(data["client_signature"].(string))
	clientVerified := verifySignature(clientPayload, clientSignature, clientPubkey)

	serverPayload, _ := hex.DecodeString(data["server_payload"].(string))
	serverSignature, _ := hex.DecodeString(data["server_signature"].(string))
	serverPrivateKey, _ := config.LoadPrivateKey("/app/key/server.key")
	serverPubkey := serverPrivateKey.PublicKey
	serverVerified := verifySignature(serverPayload, serverSignature, &serverPubkey)

    if clientVerified && serverVerified {
        if action == "register" {
			fmt.Println("Register Namespace")
			fmt.Println(data)
			dbAddNamespace(c, data)
        } 
    } else {
        c.JSON(http.StatusMultipleChoices, gin.H{"status": "Key Sign Challenge FAILED"})
    }
}

func cliRegisterNamespace(c *gin.Context) {
	var requestData map[string]interface{}
	if err := c.BindJSON(&requestData); err != nil {
		fmt.Println("Bad Request")
		c.JSON(http.StatusBadRequest, gin.H{"status": "Bad Request"})
		return
	}
	fmt.Println(requestData)
	access_token := requestData["access_token"]
	if access_token == nil {
		fmt.Println("Access Token is nil")
	} else {
		payload := url.Values{}
		payload.Set("access_token", access_token.(string)) // Replace with your actual payload data

		resp, err := http.PostForm("https://cilogon.org/oauth2/userinfo", payload)
		if err != nil {
			panic(err)
		}

		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}

		requestData["identity"] = string(body)
		keySignChallenge(c, requestData, "register")
		return 

	}

	identity_required := requestData["identity_required"]

	if identity_required == nil || identity_required == "false" {
		fmt.Println("Identity is not required")
		keySignChallenge(c, requestData, "register")
		return 
	}

	device_code := requestData["device_code"]
	if device_code == nil || device_code == "" {
		fmt.Println("Get Device Code")
		payload := url.Values{}
		payload.Set("client_id", OIDCClientID)
		payload.Set("client_secret", OIDCClientSecret)
		payload.Set("scope", OIDCScope)
	
		response, err := http.PostForm(DeviceAuthEndpoint, payload)
		if err != nil {
			log.Fatalln(err)
		}
		defer response.Body.Close()

		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			log.Fatalln(err)
		}

		var res Response
		err = json.Unmarshal(body, &res)
		if err != nil {
			log.Fatalln(err)
		}

		verificationURL := res.VerificationURLComplete
		deviceCode := res.DeviceCode

		c.JSON(http.StatusOK, gin.H{
			"device_code": deviceCode,
			"verification_url": verificationURL,
		})
		return 
	} else {
		fmt.Println("Verify Device Code")
		payload := url.Values{}
		payload.Set("client_id", OIDCClientID)
		payload.Set("client_secret", OIDCClientSecret)
		payload.Set("device_code", device_code.(string))
		payload.Set("grant_type", GrantType)

		response, err := http.PostForm(TokenEndpoint, payload)
		if err != nil {
			log.Fatalln(err)
		}
		defer response.Body.Close()

		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			log.Fatalln(err)
		}

		var tokenResponse TokenResponse
		err = json.Unmarshal(body, &tokenResponse)
		if err != nil {
			log.Fatalln(err)
		}

		if tokenResponse.AccessToken == "" {
			c.JSON(http.StatusOK, gin.H{
				"status": "PENDING",
			})
		} else {
			c.JSON(http.StatusOK, gin.H{
				"status": "APPROVED",
				"access_token": tokenResponse.AccessToken,
			})
		}
		return 
	}
}

func dbAddNamespace(c *gin.Context, data map[string]interface{}) {
	var ns Namespace

	ns.Prefix = data["prefix"].(string)
	pubkeyData, _ := json.Marshal(data["pubkey"].(map[string]interface{}))
	ns.Pubkey = string(pubkeyData)
	
	if err := c.ShouldBindJSON(&ns); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	fmt.Println(ns)
	err := addNamespace(db, &ns)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func dbDeleteNamespace(c *gin.Context) {
	prefix := c.Param("prefix")

	err := deleteNamespace(db, prefix)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func cliListNamespaces(c *gin.Context) {
	prefix := c.Param("prefix")

	ns, err := getNamespace(db, prefix)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, ns)
}

func dbGetAllNamespaces(c *gin.Context) {
	nss, err := getAllNamespaces(db)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	fmt.Println(nss)
	c.JSON(http.StatusOK, nss)
}

func getJwks(c *gin.Context) {
	prefix := c.Param("prefix")
	c.JSON(http.StatusOK, gin.H{"status": "Get JWKS is not implemented", "prefix": prefix})
}

func getOpenIDConfiguration(c *gin.Context) {
	prefix := c.Param("prefix")
	c.JSON(http.StatusOK, gin.H{"status": "getOpenIDConfiguration is not implemented", "prefix": prefix})
}

// func cliUpdateNamespace(c *gin.Context) {
// 	var ns Namespace
// 	if err := c.ShouldBindJSON(&ns); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
// 		return
// 	}

// 	err := updateNamespace(db, &ns)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
// 		return
// 	}

// 	c.JSON(http.StatusOK, gin.H{"status": "success"})
// }

// func registerANamespace(c *gin.Context) {
// 	c.JSON(http.StatusOK, gin.H{"status": "Register a new namespace"})
// }

// func cliListNamespaces(c *gin.Context) {
// 	// Your function here
// 	c.JSON(http.StatusOK, gin.H{"status": "List all namespaces"})
// }

// func dbDeleteNamespace(c *gin.Context) {
// 	prefix := c.Param("prefix")

// 	// Your function here
// 	c.JSON(http.StatusOK, gin.H{"status": "Delete Namespace", "prefix": prefix})
// }