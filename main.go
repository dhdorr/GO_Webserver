package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

type apiConfig struct {
	fileserverHits   int
	successfulChirps int
	DB1              *DB
	jwtSecret        string
}

func main() {
	const filepathRoot = "."
	const port = "8080"

	godotenv.Load()
	jwtSecret := os.Getenv("JWT_SECRET")

	db, err := NewDB("database.json")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("db created")

	apiCfg := apiConfig{
		fileserverHits:   0,
		successfulChirps: 0,
		DB1:              db,
		jwtSecret:        jwtSecret,
	}

	r := chi.NewRouter()
	rApi := chi.NewRouter()

	fsHandler := apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(filepathRoot))))
	r.Handle("/app", fsHandler)
	r.Handle("/app/*", fsHandler)
	rApi.Get("/healthz", handlerReadiness)
	rApi.Get("/metrics", apiCfg.getMetrics)
	rApi.Get("/reset", apiCfg.resetHits)
	// rApi.Post("/validate_chirp", apiCfg.validateChirp)
	rApi.Post("/chirps", apiCfg.validateChirp)
	rApi.Get("/chirps", apiCfg.retrieveChirps)
	rApi.Get("/chirps/{chirpID}", apiCfg.retrieveChirpsByID)
	rApi.Post("/users", apiCfg.createUser)
	rApi.Post("/login", apiCfg.loginUser)
	rApi.Put("/users", apiCfg.handlerUpdateUsers)

	r.Mount("/api", rApi)
	r.Mount("/admin", rApi)

	corsMux := middlewareCors(r)

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: corsMux,
	}

	log.Printf("Serving files from %s on port: %s\n", filepathRoot, port)
	log.Fatal(srv.ListenAndServe())
}

func middlewareCors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func handlerReadiness(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	// do something
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits++
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) resetHits(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits = 0
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hits reset to 0"))
}

func (cfg *apiConfig) getMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("<html><body><h1>Welcome, Chirpy Admin</h1><p>Chirpy has been visited %d times!</p></body></html>", cfg.fileserverHits)))
}

func (cfg *apiConfig) validateChirp(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Body string `json:"body"`
	}
	type returnVals struct {
		Body string `json:"body"`
		Id   int    `json:"id"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 500, "Something went wrong")
	}

	if len(params.Body) > 140 {
		respondWithError(w, 400, "Chirp is too long")
	}

	cleaned2 := strings.Split(params.Body, " ")

	for i, word := range cleaned2 {
		temp := strings.ToLower(word)
		if temp == "kerfuffle" || temp == "sharbert" || temp == "fornax" {
			temp = "****"
			cleaned2[i] = temp
		} else {
			cleaned2[i] = word
		}

	}

	cleaned3 := strings.Join(cleaned2, " ")

	cfg.successfulChirps += 1

	uniqueId := cfg.successfulChirps

	respBody := returnVals{

		Body: cleaned3,
		Id:   uniqueId,
	}

	cfg.DB1.CreateChirp(cleaned3)

	respondWithJSON(w, 201, respBody)
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	type errorVals struct {
		Error string `json:"error"`
	}
	respBody := errorVals{
		Error: msg,
	}
	dat, err := json.Marshal(respBody)
	if err != nil {
		w.WriteHeader(code)
		return
	}
	w.WriteHeader(code)
	w.Header().Set("Content-Type", "application/json")
	w.Write(dat)
	return
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	dat, err := json.Marshal(payload)
	if err != nil {
		respondWithError(w, 500, "Unable to marshal response")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(dat)
	return

}

type Chirp struct {
	Body string `json:"body"`
	Id   int    `json:"id"`
}

type DBStructure struct {
	Chirps map[int]Chirp `json:"chirps"`
	Users  map[int]User  `json:"users"`
}

func (cfg *apiConfig) retrieveChirps(w http.ResponseWriter, r *http.Request) {
	dbChirps, err := cfg.DB1.GetChirps()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't retrieve Chirps")
		return
	}

	chirps := []Chirp{}
	for _, dbChirp := range dbChirps {
		chirps = append(chirps, Chirp{
			Id:   dbChirp.Id,
			Body: dbChirp.Body,
		})
	}

	sort.Slice(chirps, func(i, j int) bool {
		return chirps[i].Id < chirps[j].Id
	})

	respondWithJSON(w, http.StatusOK, chirps)
}

type DB struct {
	path string
	mux  *sync.RWMutex
}

// NewDB creates a new database connection
// and creates the database file if it doesn't exist
func NewDB(path string) (*DB, error) {
	dbg := flag.Bool("debug", false, "Enable debug mode")
	flag.Parse()
	if *dbg {
		_, err := os.Stat(path)
		if err == nil {
			err = os.Remove(path)
		}
	}

	db := &DB{
		path: path,
		mux:  &sync.RWMutex{},
	}
	err := db.ensureDB()

	return db, err
}

// CreateChirp creates a new chirp and saves it to disk
func (db *DB) CreateChirp(body string) (Chirp, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}

	id := len(dbStructure.Chirps) + 1
	chirp := Chirp{
		Id:   id,
		Body: body,
	}
	dbStructure.Chirps[id] = chirp

	err = db.writeDB(dbStructure)
	if err != nil {
		return Chirp{}, err
	}

	return chirp, nil
}

// GetChirps returns all chirps in the database
func (db *DB) GetChirps() ([]Chirp, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		fmt.Print(err)
		return nil, err
	}

	chirps := make([]Chirp, 0, len(dbStructure.Chirps))
	for _, chirp := range dbStructure.Chirps {
		chirps = append(chirps, chirp)
	}

	return chirps, nil
}

// ensureDB creates a new database file if it doesn't exist
func (db *DB) ensureDB() error {
	_, err := os.ReadFile(db.path)
	if errors.Is(err, os.ErrNotExist) {
		//create db
		dbStructure := DBStructure{
			Chirps: map[int]Chirp{},
			Users:  map[int]User{},
		}
		err2 := db.writeDB(dbStructure)
		return err2
	}

	return err
}

// loadDB reads the database file into memory
func (db *DB) loadDB() (DBStructure, error) {
	db.mux.RLock()
	defer db.mux.RUnlock()

	dbStructure := DBStructure{}
	dat, err := os.ReadFile(db.path)
	if errors.Is(err, os.ErrNotExist) {
		return dbStructure, err
	}
	err = json.Unmarshal(dat, &dbStructure)
	if err != nil {
		return dbStructure, err
	}

	return dbStructure, nil
}

// writeDB writes the database file to disk
func (db *DB) writeDB(dbStructure DBStructure) error {
	db.mux.Lock()
	defer db.mux.Unlock()

	dat, err := json.Marshal(dbStructure)
	if err != nil {
		return err
	}

	err = os.WriteFile(db.path, dat, 0600)
	if err != nil {
		return err
	}
	return nil
}

func (db *DB) getChirp(id int) (Chirp, error) {
	dbstructure, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}

	chirp, ok := dbstructure.Chirps[id]
	if !ok {
		return Chirp{}, os.ErrNotExist
	}

	return chirp, nil
}

type User struct {
	ID             int    `json:"id"`
	Email          string `json:"email"`
	HashedPassword string `json:"hashed_password"`
}

func (db *DB) createNewUser(email, hashedPwd string) (User, error) {
	if _, err := db.GetUserByEmail(email); !errors.Is(err, os.ErrNotExist) {
		return User{}, errors.New("This email is already registered")
	}

	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	id := len(dbStructure.Users) + 1
	user := User{
		ID:             id,
		Email:          email,
		HashedPassword: hashedPwd,
	}
	dbStructure.Users[id] = user

	err = db.writeDB(dbStructure)
	if err != nil {
		return User{}, err
	}

	return user, nil
}

func (db *DB) GetUserByEmail(email string) (User, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	for _, user := range dbStructure.Users {
		if user.Email == email {
			return user, nil
		}
	}

	return User{}, os.ErrNotExist
}

func (cfg *apiConfig) retrieveChirpsByID(w http.ResponseWriter, r *http.Request) {
	chirpIDString := chi.URLParam(r, "chirpID")
	chirpID, err := strconv.Atoi(chirpIDString)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid Chirp ID")
		return
	}

	dbChirp, err := cfg.DB1.getChirp(chirpID)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Couldn't get Chirp")
		return
	}

	respondWithJSON(w, http.StatusOK, Chirp{
		Id:   dbChirp.Id,
		Body: dbChirp.Body,
	})
}

func (cfg *apiConfig) createUser(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	type returnVals struct {
		Email    string `json:"email"`
		Id       int    `json:"id"`
		Password string `json:"-"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 500, "Something went wrong")
		return
	}

	cfg.successfulChirps += 1

	//uniqueId := cfg.successfulChirps
	hashedPwdByte, err := bcrypt.GenerateFromPassword([]byte(params.Password), 10)

	// respBody := returnVals{
	// 	Password: string(hashedPwdByte),
	// 	Email:    params.Email,
	// 	Id:       uniqueId,
	// }

	user, err2 := cfg.DB1.createNewUser(params.Email, string(hashedPwdByte))
	if err2 != nil {
		respondWithError(w, http.StatusInternalServerError, err2.Error())
		return
	}

	respBody := returnVals{
		Email: user.Email,
		Id:    user.ID,
	}

	respondWithJSON(w, 201, respBody)
}

type rUser struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
}

func (cfg *apiConfig) loginUser(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Password   string `json:"password"`
		Email      string `json:"email"`
		Expiration int    `json:"expires_in_seconds"`
	}

	type respVals struct {
		rUser
		Token string `json:"token"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't decode parameters")
		return
	}

	user, err := cfg.DB1.GetUserByEmail(params.Email)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't get user")
		return
	}

	err = checkPwdHash(params.Password, user.HashedPassword)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid password")
		return
	}

	defaultExpiration := 60 * 60 * 24
	if params.Expiration == 0 {
		params.Expiration = defaultExpiration
	} else if params.Expiration > defaultExpiration {
		params.Expiration = defaultExpiration
	}

	// jwt token auth
	token, err := makeJWT(user.ID, cfg.jwtSecret, time.Duration(params.Expiration)*time.Second)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't create JWT")
		return
	}

	respondWithJSON(w, http.StatusOK, respVals{
		rUser: rUser{
			ID:    user.ID,
			Email: user.Email,
		},
		Token: token,
	},
	)

}

func checkPwdHash(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func makeJWT(userID int, tokenSecret string, expiresIn time.Duration) (string, error) {
	signingKey := []byte(tokenSecret)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiresIn)),
		Subject:   fmt.Sprintf("%d", userID),
	})

	return token.SignedString(signingKey)
}

func (cfg *apiConfig) handlerUpdateUsers(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	type response struct {
		rUser
	}

	token, err := GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Couldn't find JWT")
		return
	}

	subject, err := ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Couldn't validate JWT")
		return
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't decode parameters")
		return
	}

	hashedPwd, err := HashPassword(params.Password)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't hash password")
		return
	}

	userIDInt, err := strconv.Atoi(subject)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't parse user ID")
		return
	}

	user, err := cfg.DB1.UpdateUser(userIDInt, params.Email, hashedPwd)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't create user")
		return
	}

	respondWithJSON(w, http.StatusOK, response{
		rUser: rUser{
			ID:    user.ID,
			Email: user.Email,
		},
	})

}

func GetBearerToken(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("Authorization required")
	}
	splitAuth := strings.Split(authHeader, " ")
	if len(splitAuth) < 2 || splitAuth[0] != "Bearer" {
		return "", errors.New("malformed authorization in header")
	}
	return splitAuth[1], nil
}

func HashPassword(password string) (string, error) {
	dat, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(dat), nil
}

func ValidateJWT(tokenString, tokenSecret string) (string, error) {
	claimsStruct := jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(
		tokenString,
		&claimsStruct,
		func(token *jwt.Token) (interface{}, error) { return []byte(tokenSecret), nil },
	)
	if err != nil {
		return "", err
	}

	userIDString, err := token.Claims.GetSubject()
	if err != nil {
		return "", err
	}

	return userIDString, nil
}

func (db *DB) UpdateUser(id int, email, hashedPassword string) (User, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	user, ok := dbStructure.Users[id]
	if !ok {
		return User{}, errors.New("User does not exist")
	}

	user.Email = email
	user.HashedPassword = hashedPassword
	dbStructure.Users[id] = user

	err = db.writeDB(dbStructure)
	if err != nil {
		return User{}, err
	}

	return user, nil
}
