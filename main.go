// A simple Go web application demonstrating Google OAuth2 authentication.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// User represents a Google user.
type User struct {
	Email string `json:"email"`
	Name  string `json:"name"`
	Pic   string `json:"picture"`
}

// Global variables
var (
	oauthCfg    *oauth2.Config
	ctx         = context.Background()
	redisClient *redis.Client
)

// Entry point of the application
func main() {

	//Load .env file
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: .env file not found")
	}

	redisClient = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379", // or your Redis hostname:port
		Password: "",               // set if Redis requires auth
		DB:       0,
	})

	// test connection
	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.Fatalf("❌ Failed to connect to Redis: %v", err)
	}
	log.Println("✅ Connected to Redis")

	// Initialize OAuth2 configuration
	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	redirectURL := os.Getenv("REDIRECT_URL")

	// Set configs into oauthCfg
	oauthCfg = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		Endpoint:     google.Endpoint,
	}

	// Set up HTTP routes
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/logout", handleLogout)

	log.Println("🚀 Server started at http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	user, ok := getUser(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if !ok {
		fmt.Fprint(w, `<h1>Google Login Demo</h1><a href="/login">Login with Google</a>`)
		return
	}

	data, _ := json.MarshalIndent(user, "", "  ")
	fmt.Fprintf(w, `<h1>Welcome %s</h1><img src="%s" style="height:80px;border-radius:50%%;"><pre>%s</pre><a href="/logout">Logout</a>`, user.Name, user.Pic, data)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	url := oauthCfg.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "code not found", http.StatusBadRequest)
		return
	}

	token, err := oauthCfg.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "token exchange failed", http.StatusInternalServerError)
		return
	}

	client := oauthCfg.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		http.Error(w, "failed to get user info", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		http.Error(w, "failed to decode user info", http.StatusInternalServerError)
		return
	}

	sessionID := fmt.Sprintf("%d", time.Now().UnixNano())

	userJSON, _ := json.Marshal(user)
	err = redisClient.Set(ctx, "session:"+sessionID, userJSON, time.Hour).Err()
	if err != nil {
		http.Error(w, "failed to store session", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "session",
		Value:   sessionID,
		Expires: time.Now().Add(1 * time.Hour),
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie("session")
	if c != nil {
		redisClient.Del(ctx, "session:"+c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "session",
		Value:   "",
		Expires: time.Unix(0, 0),
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func getUser(r *http.Request) (User, bool) {
	c, err := r.Cookie("session")
	if err != nil {
		return User{}, false
	}

	val, err := redisClient.Get(ctx, "session:"+c.Value).Result()
	if err == redis.Nil {
		return User{}, false // session not found
	} else if err != nil {
		log.Println("Redis error:", err)
		return User{}, false
	}

	var user User
	if err := json.Unmarshal([]byte(val), &user); err != nil {
		return User{}, false
	}

	return user, true
}
