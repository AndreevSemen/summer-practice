package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

const (
	AccessToken  = iota
	RefreshToken = iota
)

type Token struct {
	TokenType  int
	Token      string
	Expiration time.Time
}

func NewAccessToken() *Token {
	return &Token{TokenType: AccessToken}
}

func NewRefreshToken() *Token {
	return &Token{TokenType: RefreshToken}
}

type ClientHandlerFunc func(clientId, clientSecret string) (client interface{})

type CodeHandlerFunc func(code, redirectUri string) (user interface{})

type PasswordGrantHandlerFunc func(username string, password string) (user interface{})

type CreateTokenHandlerFunc func(token *Token, client interface{}, user interface{}) error

type AuthServer struct {
	ClientHandler        ClientHandlerFunc
	CodeHandler          CodeHandlerFunc
	PasswordGrantHandler PasswordGrantHandlerFunc
	CreateTokenHandler   CreateTokenHandlerFunc
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

func NewServer() *AuthServer {
	return new(AuthServer)
}

var DefaultServer = NewServer()

func ClientHandler(fn ClientHandlerFunc) {
	DefaultServer.ClientHandler = fn
}

func PasswordGrantHandler(fn PasswordGrantHandlerFunc) {
	DefaultServer.PasswordGrantHandler = fn
}

func CreateTokenHandler(fn CreateTokenHandlerFunc) {
	DefaultServer.CreateTokenHandler = fn
}

func CodeHandler(fn CodeHandlerFunc) {
	DefaultServer.CodeHandler = fn
}

func outputError(w http.ResponseWriter, err Error) {
	w.WriteHeader(err.Code)
	writeResponse(w, err.Json())
}

func output(w http.ResponseWriter, response interface{}) {
	if out, err := json.Marshal(response); err != nil {
		outputError(w, NewServerError(""))
	} else {
		w.WriteHeader(http.StatusOK)
		writeResponse(w, string(out))
	}
}

func writeResponse(w http.ResponseWriter, response string) {
	w.Header().Add("Content-Type", "application/json;charset=UTF-8")
	w.Header().Add("Cache-Control", "no-store")
	w.Header().Add("Pragma", "no-cache")
	fmt.Fprint(w, response)
}

func AuthValidate(r *http.Request) error {
	responseType := r.FormValue("response_type")
	if responseType == "" {
		return NewInvalidRequestError("Required parameter is missing: response_type")
	}

	clientId := r.FormValue("client_id")
	if clientId == "" {
		return NewInvalidRequestError("Required parameter is missing: client_id")
	}

	redirectUri := r.FormValue("redirect_uri")
	if redirectUri != "" {
		_, err := url.ParseRequestURI(redirectUri)
		if err != nil {
			return NewInvalidRequestError("Invalid redirect_uri")
		}
	}

	return nil
}

func authRedirect(w http.ResponseWriter, r *http.Request, query url.Values) {
	if state := r.FormValue("state"); state != "" {
		query.Add("state", state)
	}

	redirectUri := r.FormValue("redirect_uri")
	uri, err := url.ParseRequestURI(redirectUri)
	if err != nil {
		panic(err)
	}
	uri.RawQuery = query.Encode()
	http.Redirect(w, r, uri.String(), http.StatusFound)
}

func AuthError(w http.ResponseWriter, r *http.Request, err Error) {
	query := url.Values{}
	query.Add("error", err.ErrorName)
	if err.Description != "" {
		query.Add("error_description", err.Description)
	}
	if err.Uri != "" {
		query.Add("error_uri", err.Uri)
	}
	authRedirect(w, r, query)
}

func AuthSuccess(w http.ResponseWriter, r *http.Request, code string) {
	query := url.Values{}
	query.Add("code", code)
	authRedirect(w, r, query)
}

func (a *AuthServer) createAndOutputTokens(
	w http.ResponseWriter,
	client interface{},
	user interface{},
) {
	accessToken := NewAccessToken()
	err := a.CreateTokenHandler(accessToken, client, user)
	if err != nil {
		outputError(w, NewServerError(""))
		return
	}

	refreshToken := NewRefreshToken()
	err = a.CreateTokenHandler(refreshToken, client, user)
	if err != nil {
		outputError(w, NewServerError(""))
		return
	}

	response := new(TokenResponse)
	response.AccessToken = accessToken.Token
	response.ExpiresIn = int(accessToken.Expiration.Sub(time.Now()).Seconds()) + 1
	response.RefreshToken = refreshToken.Token
	response.TokenType = "Bearer"

	output(w, response)
}

func (a *AuthServer) handleAuthorizationCodeTokenRequest(
	w http.ResponseWriter,
	r *http.Request,
	client interface{},
) {
	code := r.FormValue("code")
	redirectUri := r.FormValue("redirect_uri")

	if code == "" {
		outputError(w, NewInvalidRequestError("Required parameter is missing: code"))
		return
	}
	if redirectUri == "" {
		outputError(w, NewInvalidRequestError("Required parameter is missing: redirect_uri"))
		return
	}

	if user := a.CodeHandler(code, redirectUri); user != nil {
		a.createAndOutputTokens(w, client, user)
		return
	}

	outputError(w, NewAccessDeniedError(""))
	return
}

func (a *AuthServer) handlePasswordTokenRequest(
	w http.ResponseWriter,
	r *http.Request,
	client interface{},
) {
	if a.PasswordGrantHandler == nil {
		outputError(w, NewUnsupportedGrantTypeError("'password' grant type is not supported"))
		return
	}

	username := r.FormValue("username")
	if username == "" {
		outputError(w, NewInvalidRequestError("Required parameter is missing: username"))
		return
	}

	password := r.FormValue("password")
	if password == "" {
		outputError(w, NewInvalidRequestError("Required parameter is missing: password"))
		return
	}

	if user := a.PasswordGrantHandler(username, password); user != nil {
		a.createAndOutputTokens(w, client, user)
		return
	}

	outputError(w, NewInvalidGrantError(""))
	return
}

func (a *AuthServer) TokenEndpoint(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	grantType := r.FormValue("grant_type")
	clientId := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	if grantType == "" {
		outputError(w, NewInvalidRequestError("Required parameter is missing: grant_type"))
		return
	}
	if clientId == "" {
		outputError(w, NewInvalidRequestError("Required parameter is missing: client_id"))
		return
	}
	if clientSecret == "" {
		outputError(w, NewInvalidRequestError("Required parameter is missing: client_secret"))
		return
	}

	if client := a.ClientHandler(clientId, clientSecret); client != nil {
		switch grantType {
		case "authorization_code":
			a.handleAuthorizationCodeTokenRequest(w, r, client)
		case "password":
			a.handlePasswordTokenRequest(w, r, client)
		default:
			outputError(w, NewUnsupportedGrantTypeError(""))
		}
		return
	}

	outputError(w, NewInvalidClientError(""))
	return
}

func TokenEndpoint(w http.ResponseWriter, r *http.Request) {
	DefaultServer.TokenEndpoint(w, r)
}
