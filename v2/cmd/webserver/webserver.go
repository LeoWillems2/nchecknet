package main


import (
	"github.com/LeoWillems2/nchecknet/pkg/sharedlib"
	"github.com/gorilla/websocket"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
	"strings"
	"errors"
	"context"
	"github.com/golang-jwt/jwt/v5"
)

// YConfig holds the configuration stuff
var YConfig sharedlib.YamlConfig

// JWT stuff:
var jwtSecret = []byte(YConfig.Server.JWTSecret)

type CustomClaims struct {
        Username string `json:"username"`
        jwt.RegisteredClaims
}

// UserLogin maps to the input's in index.html
type UserLogin struct {
        Username string `json:"username"`
        Password string `json:"password"`
}

// LogOffHandler() invalidates the cookie at the client and removes the token from the dbUser data.
func LogOffHandler(w http.ResponseWriter, r *http.Request) {
	expirationTime := time.Now()
	http.SetCookie(w, &http.Cookie{
		Name:     "nchecknettoken", // Name of the cookie
		Value:    "",
		Expires:  expirationTime,
		HttpOnly: true, // ⬅️ CRITICAL: Prevents client-side JavaScript access (XSS defense)
		Secure:   true, // ⬅️ CRITICAL: Only send over HTTPS (SHOULD be enabled in production)
		SameSite: http.SameSiteStrictMode, // Good defense against CSRF
		Path:     "/",
	})

	_x := r.Context().Value("claims")
        x, ok := _x.(*CustomClaims)
	if !ok {
		log.Println("Should not happen: claim has wrong type?")
		return
	}
	sharedlib.UpdateUserToken(x.Username, "")

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Logoff successful.")
}

/* LoginHandler() is the JWT login handler and creates the cookie with a token and a life span of 24 hours.
   The token is stored in de dbUser document in the UsersCollection.
   The jwtSecret is read from the Yaml config at server start.
*/
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var creds UserLogin
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	u, err := sharedlib.GetUserByName(creds.Username)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if !sharedlib.CheckPasswordHash(creds.Password, u.PassHash) {
		http.Error(w, "Invalid credentials.", http.StatusUnauthorized)
		return
	}

	// Create the JWT claims
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &CustomClaims{
		Username: creds.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	// Create and sign the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Internal server error: could not create token", http.StatusInternalServerError)
		return
	}

	// 🍪 Set the JWT as an HTTP-Only Secure Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "nchecknettoken", // Name of the cookie
		Value:    tokenString,
		Expires:  expirationTime,
		HttpOnly: true, // ⬅️ CRITICAL: Prevents client-side JavaScript access (XSS defense)
		Secure:   true, // ⬅️ CRITICAL: Only send over HTTPS (SHOULD be enabled in production)
		SameSite: http.SameSiteStrictMode, // Good defense against CSRF
		Path:     "/",
	})

	sharedlib.UpdateUserToken(creds.Username, tokenString)

	// Send a simple success message
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Login successful. JWT set in HTTP-only cookie.")
}

// AuthMiddleware(): the authentication middleware (wrapper) that checks for a valid JWT (from a cookie)
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// Try to read the token from the "jwt_token" cookie
		cookie, err := r.Cookie("nchecknettoken")
		if err != nil {
			// If no cookie, check for Authorization Header as a fallback (for non-browser clients)
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
				// Handle Bearer token logic here (if you need both methods)
				// For this example, we'll focus on the cookie, so we skip detailed Bearer logic.
			}
			
			if errors.Is(err, http.ErrNoCookie) {
				http.Error(w, "Unauthorized: JWT cookie not found", http.StatusUnauthorized)
				return
			}
			http.Error(w, "Unauthorized: Failed to read cookie", http.StatusUnauthorized)
			return
		}
		
		tokenString := cookie.Value // The JWT is the cookie's value

		// Parse and validate the token
		claims := &CustomClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSecret, nil
		})

		if err != nil {
			if errors.Is(err, jwt.ErrTokenExpired) {
				http.Error(w, "Token is expired", http.StatusUnauthorized)
				return
			}
			http.Error(w, fmt.Sprintf("Invalid token: %v", err), http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			http.Error(w, "Token is invalid", http.StatusUnauthorized)
			return
		}

		// Add the user claims to the request context
		ctx := context.WithValue(r.Context(), "claims", claims)
		r = r.WithContext(ctx)

		// Call the next handler
		next.ServeHTTP(w, r)
	}
}


// Upgrader is used to upgrade HTTP connections to WebSocket connections.
var upgrader = websocket.Upgrader{
        CheckOrigin: func(r *http.Request) bool {
                // Allow all connections by default
                return true
        },
}

// handleWebSocket() is protected by the middleware and handles WebSocket requests from clients.
func handleWebSocket(w http.ResponseWriter, r *http.Request) {

	// Get the user from the context
    _x := r.Context().Value("claims")
    x, ok := _x.(*CustomClaims)
    if !ok {
        log.Println("claim has wrong type?")
        return
    }

	user, err := sharedlib.GetUserByName(x.Username)
	if err != nil {
		log.Println("NO User?");
		return
	}

	// structs for the websocket I/O
	type MessageIn struct {
		Function string
		Hostname string
		SessionID string
		Data string
		Hide string
		Csum string
		ChartType string
	}

	type MessageOut struct {
		Function string
		Hostname string
		ArrData []string
	}

	// Upgrade the HTTP connection to a WebSocket connection
        conn, err := upgrader.Upgrade(w, r, nil)
        if err != nil {
                log.Println("Upgrade error:", err)
                return
        }
        defer conn.Close()

        // Read messages from the WebSocket connection
        for {
            _, message, err := conn.ReadMessage()
             if err != nil {
                  log.Println("Read error:", err)
                  break
        	  }

            mi := MessageIn{}
            err = json.Unmarshal(message, &mi)
            if err != nil {
                 panic(err)
            }

			mo := MessageOut{}
			switch (mi.Function){
			case "GetServers":
				mo.Function = "FillServers"
				alls, _ := sharedlib.GetServers(user.Owner) 
				for _, s := range alls {
					mo.ArrData = append(mo.ArrData, s.Hostname)
				}
			case "GetSessionIDs":
				if sharedlib.NoAccess2DB(user.Owner, mi.Hostname) { return }
				mo.Function = "FillSessionIDs"
				mo.Hostname = mi.Hostname;
				alls, _, _ := sharedlib.GetSessionIDs(mi.Hostname) 
				mo.ArrData = alls
			case "GetNmapCollector":
				if sharedlib.NoAccess2DB(user.Owner, mi.Hostname) { return }
				mo.Function = "FillNmapCollector"
				t, _ := sharedlib.CreateNmapCollectorPy(mi.Hostname, mi.SessionID, mi.Data[4:], YConfig.Collector.CollectorURL)
				mo.ArrData = append(mo.ArrData,t)
			case "GetNmapSuggestion":
				if sharedlib.NoAccess2DB(user.Owner, mi.Hostname) { return }
				mo.Function = "FillNmapSuggestion"
				sn, err := sharedlib.GetServerByHostname(mi.Hostname)
				
				if err != nil {
					log.Println("GetNmapSuggestion", err, mi.Hostname, sn)
					continue
				}
				mo.Hostname = mi.Hostname
				txt := sharedlib.GenPic(sn.Key,mi.SessionID)
				mo.ArrData = append(mo.ArrData,txt)
			case "GetData":
				if sharedlib.NoAccess2DB(user.Owner, mi.Hostname) { return }
				mo.Function = "FillData"
				mo.Hostname = mi.Hostname
				t, err := sharedlib.PrettyPrintServerData("All:"+ mi.Hostname+ ":"+mi.SessionID )
				if err != nil {
					log.Println("GetData", err, mi.Hostname)
					continue
				}
				mo.ArrData = append(mo.ArrData,t)
			case "GetUfwListenChart":
				if sharedlib.NoAccess2DB(user.Owner, mi.Hostname) { return }
				t := ""
				switch mi.ChartType {
				case "ufwlisten":
					t, err = sharedlib.CompareFromUFWViewpoint(mi.Hostname, mi.SessionID, mi.Hide)
						if err != nil {
							continue
						}	
				}
				mo.Function = "FillChartReport"
				mo.ArrData = append(mo.ArrData,t)
				
			case "HideFwrule":
				if sharedlib.NoAccess2DB(user.Owner, mi.Hostname) { return }
				sharedlib.HideFwrule(mi.Hostname, mi.SessionID, mi.Csum)
				
				t, err := sharedlib.CompareFromUFWViewpoint(mi.Hostname, mi.SessionID,mi.Hide)
				if err != nil {
						continue
				}
				mo.Function = "FillChartReport"
				mo.ArrData = append(mo.ArrData,t)
			
			case "ChangeFwComment":
				if sharedlib.NoAccess2DB(user.Owner, mi.Hostname) { return }
				sharedlib.ChangeFwComment(mi.Hostname, mi.SessionID, mi.Csum, mi.Data)
			}

			/*
			moj, err := json.Marshal(mo)

			if err != nil {
				log.Println("mo marshal failed", err)
				continue
			}

            // Echo the message back to the client
            if err := conn.WriteMessage(messageType, moj); err != nil {
                log.Println("Write error:", err)
            }
			*/
        }
        //log.Println("Client disconnected")
}

func main() {
	var err error
	
	// Read the config file
	YConfig, err = sharedlib.GetYamlConfig("etc/nchecknet.yml")
	if err != nil {
		log.Fatalln(err)
		return
	}

	fileserver := http.FileServer(http.Dir("./webroot"))
	http.Handle("/", fileserver)

	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/ws", AuthMiddleware(handleWebSocket))
	http.HandleFunc("/logoff", AuthMiddleware(LogOffHandler))
	
	sharedlib.DBConnect()

	// Start the server
	port := ":8086"
	fmt.Printf("Server starting on port %s\n", port)

	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}
