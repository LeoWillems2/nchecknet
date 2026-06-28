// Package main implements the nchecknet web server.
//
// It serves the single-page app from the configured webroot, handles JWT-based
// login/logoff over HTTP, and exposes all UI operations through a single
// authenticated WebSocket endpoint (/ws). All business logic is delegated to
// the sharedlib package; the webserver only handles transport and auth.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/LeoWillems2/nchecknet/pkg/sharedlib"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
)

// YConfig holds the configuration loaded from etc/nchecknet.yml at startup.
var YConfig sharedlib.YamlConfig

// jwtSecret is the HMAC key used to sign and verify JWT tokens.
// WARNING: this is evaluated at package-init time, before main() loads the config,
// so it will always be []byte(""). The secret must be moved into main() after
// GetYamlConfig returns for token signing to actually use the configured value.
var jwtSecret = []byte(YConfig.Server.JWTSecret)

// CustomClaims extends jwt.RegisteredClaims with the authenticated username,
// which is carried in the request context after middleware validation.
type CustomClaims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// UserLogin is the JSON body expected by the /login endpoint.
type UserLogin struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LogOffHandler expires the JWT cookie in the browser and clears the stored token
// from the user's MongoDB document, preventing further use of the old token.
func LogOffHandler(w http.ResponseWriter, r *http.Request) {
	expirationTime := time.Now()
	http.SetCookie(w, &http.Cookie{
		Name:     "nchecknettoken", // Name of the cookie
		Value:    "",
		Expires:  expirationTime,
		HttpOnly: true,                    // ⬅️ CRITICAL: Prevents client-side JavaScript access (XSS defense)
		Secure:   true,                    // ⬅️ CRITICAL: Only send over HTTPS (SHOULD be enabled in production)
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

// LoginHandler authenticates the user and issues a 24-hour JWT in an HttpOnly Secure cookie.
// The token is also written to the user's MongoDB document so it can be invalidated on logoff.
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
		HttpOnly: true,                    // ⬅️ CRITICAL: Prevents client-side JavaScript access (XSS defense)
		Secure:   true,                    // ⬅️ CRITICAL: Only send over HTTPS (SHOULD be enabled in production)
		SameSite: http.SameSiteStrictMode, // Good defense against CSRF
		Path:     "/",
	})

	sharedlib.UpdateUserToken(creds.Username, tokenString)

	// Send a simple success message
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Login successful. JWT set in HTTP-only cookie.")
}

// AuthMiddleware validates the JWT from the "nchecknettoken" cookie and, on success,
// injects the parsed CustomClaims into the request context under the key "claims".
// A Bearer-token fallback is stubbed but not implemented.
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		cookie, err := r.Cookie("nchecknettoken")
		if err != nil {
			// Bearer token fallback — not yet implemented.
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
				// placeholder: Bearer logic would go here
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

// upgrader promotes HTTP connections to WebSocket.
// CheckOrigin returns true unconditionally — restrict this in production if the
// webserver is exposed on a public interface.
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// handleWebSocket is the single WebSocket endpoint for all UI operations.
// It reads JSON MessageIn frames in a loop and dispatches on MessageIn.Function,
// writing a JSON MessageOut reply after each message.
// The connection is closed when the client disconnects or a read error occurs.
func handleWebSocket(w http.ResponseWriter, r *http.Request) {

	_x := r.Context().Value("claims")
	x, ok := _x.(*CustomClaims)
	if !ok {
		log.Println("claim has wrong type?")
		return
	}

	user, err := sharedlib.GetUserByName(x.Username)
	if err != nil {
		log.Println("NO User?")
		return
	}

	// MessageIn is the client-to-server frame. Not all fields are used by every function:
	// Function  — the operation to perform (e.g. "GetServers", "HideFwrule")
	// Hostname  — target server FQDN
	// SessionID — YYYYMMDD session to operate on
	// Data      — function-specific payload (e.g. comment text, interface index with "IFN-" prefix)
	// Hide      — "unhide" to show suppressed items; empty to hide them
	// Csum      — SHA-256 checksum (with leading type byte) identifying a rule or listener
	// ChartType — "fwlistenchart" or "nmapchart" for GetFwListenChart
	type MessageIn struct {
		Function       string
		Hostname       string
		SessionID      string
		Data           string
		Hide           string
		Csum           string
		ChartType      string
		BaselineServer bool
		BaselineNmap   bool // declared but not currently acted on
		AllSessions    bool
	}

	// MessageOut is the server-to-client reply frame.
	// ArrData carries the payload (chart HTML, session IDs, hostnames, etc.).
	// BaselineServer / BaselineServerID reflect whether the requested session is the current baseline.
	// BaselineNmap / BaselineNmapID are reserved for a future nmap baseline feature.
	type MessageOut struct {
		Function         string
		Hostname         string
		ArrData          []string
		BaselineServer   bool
		BaselineNmap     bool
		BaselineServerID string
		BaselineNmapID   string
		AlertsJSON       string
		NmapAlertsJSON   string
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
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			log.Println("Read error:", err)
			break
		}

		mi := MessageIn{}
		err = json.Unmarshal(message, &mi)
		if err != nil {
			panic(err)
		}

		//log.Println(mi.Function)

		mo := MessageOut{}
		switch mi.Function {
		case "GetServers":
			mo.Function = "FillServers"
			alls, _ := sharedlib.GetServers(user)
			for _, s := range alls {
				mo.ArrData = append(mo.ArrData, s.Hostname)
			}
		case "GetSessionIDs":
			if sharedlib.NoAccess2DB(user, mi.Hostname) {
				return
			}
			mo.Function = "FillSessionIDs"
			mo.Hostname = mi.Hostname
			alls, _, _ := sharedlib.GetSessionIDs(mi.Hostname)
			// Keep only the most recent MaxSessionIDSelect sessions (tail of the sorted slice).
			if len(alls) > YConfig.Server.MaxSessionIDSelect {
				alls = alls[len(alls)-YConfig.Server.MaxSessionIDSelect:]
			}
			mo.ArrData = alls
		case "GetNmapCollector":
			if sharedlib.NoAccess2DB(user, mi.Hostname) {
				return
			}
			mo.Function = "FillNmapCollector"
			// mi.Data carries the button id "IFN-<index>"; strip the 4-char "IFN-" prefix to get the index.
			t, _ := sharedlib.CreateNmapCollectorPy(mi.Hostname, mi.SessionID, mi.Data[4:], YConfig.Collector.CollectorURL)
			mo.ArrData = append(mo.ArrData, t)
		case "GetNmapSuggestion":
			if sharedlib.NoAccess2DB(user, mi.Hostname) {
				return
			}
			mo.Function = "FillNmapSuggestion"
			sn, err := sharedlib.GetServerByHostname(mi.Hostname)

			if err != nil {
				log.Println("GetNmapSuggestion", err, mi.Hostname, sn)
				continue
			}
			mo.Hostname = mi.Hostname
			txt := sharedlib.GenPic(sn.Key, mi.SessionID)
			mo.ArrData = append(mo.ArrData, txt)
		case "SetBaselineServer":
			if sharedlib.NoAccess2DB(user, mi.Hostname) {
				return
			}
			// Always delete first; only re-insert when BaselineServer is true (toggle pattern).
			sharedlib.DeleteBaseline(mi.Hostname)
			if mi.BaselineServer {
				sharedlib.SetBaseline(mi.Hostname, mi.SessionID)
			}
		case "GetData":
			if sharedlib.NoAccess2DB(user, mi.Hostname) {
				return
			}
			mo.Function = "FillData"
			mo.Hostname = mi.Hostname
			t, err := sharedlib.PrettyPrintServerData("All:" + mi.Hostname + ":" + mi.SessionID)
			if err != nil {
				log.Println("GetData", err, mi.Hostname)
				continue
			}
			mo.ArrData = append(mo.ArrData, t)
		case "GetFwListenChart":
			if sharedlib.NoAccess2DB(user, mi.Hostname) {
				return
			}
			t := ""
			switch mi.ChartType {
			case "fwlistenchart":
				t, err = sharedlib.CompareFromFWViewpoint(mi.Hostname, mi.SessionID, mi.Hide, user.AccessRight)
				if err != nil {
					continue
				}
			
			case "nmapchart":
				t, err = sharedlib.CompareFromNMAPViewpoint(mi.Hostname, mi.SessionID)
				if err != nil {
					continue
				}
			}

			mo.Function = "FillChartReport"
			mo.ArrData = append(mo.ArrData, t)


			// Attach baseline metadata so the UI can highlight the baseline session.
			bm := "None"
			mo.BaselineServer = false
			b, err := sharedlib.GetBaseline(mi.Hostname)
			if err == nil {
				log.Println(mi.SessionID, b.SessionID)
				bm = b.SessionID
				if mi.SessionID == b.SessionID {
					mo.BaselineServer = true
				}
			}
			mo.BaselineServerID = bm

		case "HideFwrule":
			if sharedlib.NoAccess2DB(user, mi.Hostname) {
				return
			}
			if user.AccessRight != "w" && user.AccessRight != "a" {
				mo.Function = "Error"
				mo.ArrData = append(mo.ArrData, "No access rights")

			} else {
				sharedlib.HideFwrule(mi.Hostname, mi.SessionID, mi.Csum)

				t, err := sharedlib.CompareFromFWViewpoint(mi.Hostname, mi.SessionID, mi.Hide, user.AccessRight)
				if err != nil {
					continue
				}
				mo.Function = "FillChartReport"
				mo.ArrData = append(mo.ArrData, t)
			}
		case "HideListener":
			if sharedlib.NoAccess2DB(user, mi.Hostname) {
				return
			}
			if user.AccessRight != "w" && user.AccessRight != "a" {
				mo.Function = "Error"
				mo.ArrData = append(mo.ArrData, "No access rights")

			} else {
				sharedlib.HideListener(mi.Hostname, mi.SessionID, mi.Csum)

				t, err := sharedlib.CompareFromFWViewpoint(mi.Hostname, mi.SessionID, mi.Hide, user.AccessRight)
				if err != nil {
					continue
				}
				mo.Function = "FillChartReport"
				mo.ArrData = append(mo.ArrData, t)
			}

		case "ChangeFwComment":
			if sharedlib.NoAccess2DB(user, mi.Hostname) {
				return
			}
			if user.AccessRight != "w" && user.AccessRight != "a" {
				mo.Function = "Error"
				mo.ArrData = append(mo.ArrData, "No access rights")

			} else {
				sharedlib.ChangeFwComment(mi.Hostname, mi.SessionID, mi.Csum, mi.Data)
			}
		case "ChangeLisComment":
			if sharedlib.NoAccess2DB(user, mi.Hostname) {
				return
			}
			if user.AccessRight != "w" && user.AccessRight != "a" {
				mo.Function = "Error"
				mo.ArrData = append(mo.ArrData, "No access rights")

			} else {
				sharedlib.ChangeLisComment(mi.Hostname, mi.SessionID, mi.Csum, mi.Data)
			}

		case "GetNmapAlerts":
			if sharedlib.NoAccess2DB(user, mi.Hostname) {
				return
			}
			mo.Function = "FillNmapAlerts"
			var nmapAlerts []sharedlib.NmapAlertOut
			if mi.AllSessions {
				nmapAlerts, err = sharedlib.GetNmapAlertsByHostname(mi.Hostname)
			} else {
				nmapAlerts, err = sharedlib.GetNmapAlertsBySession(mi.Hostname, mi.SessionID)
			}
			if err != nil {
				log.Println("GetNmapAlerts", err)
				mo.NmapAlertsJSON = "[]"
				break
			}
			if nmapAlerts == nil {
				mo.NmapAlertsJSON = "[]"
			} else {
				b, _ := json.Marshal(nmapAlerts)
				mo.NmapAlertsJSON = string(b)
			}

		case "GetServerAlerts":
			if sharedlib.NoAccess2DB(user, mi.Hostname) {
				return
			}
			mo.Function = "FillServerAlerts"
			var alerts []sharedlib.ServerAlertOut
			if mi.AllSessions {
				alerts, err = sharedlib.GetServerAlertsByHostname(mi.Hostname)
			} else {
				alerts, err = sharedlib.GetServerAlertsBySession(mi.Hostname, mi.SessionID)
			}
			if err != nil {
				log.Println("GetServerAlerts", err)
				mo.AlertsJSON = "[]"
				break
			}
			if alerts == nil {
				mo.AlertsJSON = "[]"
			} else {
				b, _ := json.Marshal(alerts)
				mo.AlertsJSON = string(b)
			}

		}

		moj, err := json.Marshal(mo)

		if err != nil {
			log.Println("mo marshal failed", err)
			continue
		}

		// Answer
		if err := conn.WriteMessage(messageType, moj); err != nil {
			log.Println("Write error:", err)
		}
	}
	//log.Println("Client disconnected")
}

// main loads config, connects to MongoDB, registers routes, and starts the HTTP server.
//
// Routes:
//
//	/        — static file server (webroot, unauthenticated)
//	/login   — JWT login (unauthenticated)
//	/logoff  — JWT logoff (requires valid cookie)
//	/ws      — WebSocket API (requires valid cookie)
func main() {
	var err error

	YConfig, err = sharedlib.GetYamlConfig("etc/nchecknet.yml")
	if err != nil {
		log.Fatalln(err)
		return
	}

	log.Println(YConfig.Server.Webroot)
	fileserver := http.FileServer(http.Dir(YConfig.Server.Webroot))
	http.Handle("/", fileserver)

	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/ws", AuthMiddleware(handleWebSocket))
	http.HandleFunc("/logoff", AuthMiddleware(LogOffHandler))

	sharedlib.DBConnect(YConfig.Server.MongoDBURL)

	port := ":" + YConfig.Server.Port
	fmt.Printf("Server starting on port %s\n", port)

	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}
