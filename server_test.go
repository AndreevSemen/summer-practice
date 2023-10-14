package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	check "gopkg.in/check.v1"
)

func Test(t *testing.T) { check.TestingT(t) }

type HttpTestSuite struct{}

var _ = check.Suite(&HttpTestSuite{})

func (s *HttpTestSuite) SetUpTest(c *check.C) {
	DefaultServer = NewServer()

	CreateTokenHandler(func(token *Token, client interface{}, user interface{}) error {
		switch token.TokenType {
		case AccessToken:
			token.Token = "test_access_token"
			token.Expiration = time.Now().Add(3600 * time.Second)
		case RefreshToken:
			token.Token = "test_refresh_token"
		}
		return nil
	})

	ClientHandler(func(client_id, client_secret string) (client interface{}) {
		if client_id == "123" && (client_secret == "" || client_secret == "s3cr3t") {
			return 123
		}
		return nil
	})
}

func (s *HttpTestSuite) testInvalidRequest(c *check.C, values url.Values) {
	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	resp, err := http.PostForm(ts.URL, values)
	c.Assert(err, check.IsNil)
	c.Assert(resp.StatusCode, check.Equals, 400)

	body, err := io.ReadAll(resp.Body)
	c.Assert(err, check.IsNil)
	resp.Body.Close()

	e := Error{}
	err = json.Unmarshal(body, &e)
	c.Assert(err, check.IsNil)
	c.Assert(e.ErrorName, check.Equals, "invalid_request")
}

func (s *HttpTestSuite) TestTokenInvalidRequest(c *check.C) {
	values := make(url.Values)
	s.testInvalidRequest(c, values)

	values.Add("grant_type", "authorization_code")
	s.testInvalidRequest(c, values)

	values.Add("client_id", "123")
	s.testInvalidRequest(c, values)
}

func (s *HttpTestSuite) TestTokenUnsupportedGrantType(c *check.C) {
	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	values := make(url.Values)
	values.Add("grant_type", "bogus")
	values.Add("client_id", "123")
	values.Add("client_secret", "s3cr3t")
	resp, err := http.PostForm(ts.URL, values)
	c.Assert(err, check.IsNil)
	c.Assert(resp.StatusCode, check.Equals, 400)

	body, err := io.ReadAll(resp.Body)
	c.Assert(err, check.IsNil)
	resp.Body.Close()

	e := Error{}
	err = json.Unmarshal(body, &e)
	c.Assert(err, check.IsNil)
	c.Assert(e.ErrorName, check.Equals, "unsupported_grant_type")
}

func (s *HttpTestSuite) TestTokenInvalidClientId(c *check.C) {
	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	values := make(url.Values)
	values.Add("grant_type", "bogus")
	values.Add("client_id", "invalid")
	values.Add("client_secret", "s3cr3t")
	resp, err := http.PostForm(ts.URL, values)
	c.Assert(err, check.IsNil)
	c.Assert(resp.StatusCode, check.Equals, 400)

	body, err := io.ReadAll(resp.Body)
	c.Assert(err, check.IsNil)
	resp.Body.Close()

	e := Error{}
	err = json.Unmarshal(body, &e)
	c.Assert(err, check.IsNil)
	c.Assert(e.ErrorName, check.Equals, "invalid_client")
}

func (s *HttpTestSuite) TestTokenInvalidClientSecret(c *check.C) {
	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	values := make(url.Values)
	values.Add("grant_type", "bogus")
	values.Add("client_id", "123")
	values.Add("client_secret", "invalid")
	resp, err := http.PostForm(ts.URL, values)
	c.Assert(err, check.IsNil)
	c.Assert(resp.StatusCode, check.Equals, 400)

	body, err := io.ReadAll(resp.Body)
	c.Assert(err, check.IsNil)
	resp.Body.Close()

	e := Error{}
	err = json.Unmarshal(body, &e)
	c.Assert(err, check.IsNil)
	c.Assert(e.ErrorName, check.Equals, "invalid_client")
}

func (s *HttpTestSuite) TestTokenPassword(c *check.C) {
	PasswordGrantHandler(func(username string, password string) (user interface{}) {
		return 1
	})

	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	values := make(url.Values)
	values.Add("client_id", "123")
	values.Add("client_secret", "s3cr3t")
	values.Add("grant_type", "password")
	values.Add("username", "testuser")
	values.Add("password", "testpassword")

	resp, _ := http.PostForm(ts.URL, values)
	c.Assert(resp.StatusCode, check.Equals, 200)

	body, err := io.ReadAll(resp.Body)
	c.Assert(err, check.IsNil)
	resp.Body.Close()

	token := new(TokenResponse)
	err = json.Unmarshal(body, token)
	c.Assert(err, check.IsNil)

	c.Assert(token.AccessToken, check.Equals, "test_access_token")
	c.Assert(token.RefreshToken, check.Equals, "test_refresh_token")
	c.Assert(token.ExpiresIn, check.Equals, 3600)
	c.Assert(token.TokenType, check.Equals, "Bearer")
}

func (s *HttpTestSuite) TestTokenPasswordInvalidRequest(c *check.C) {
	PasswordGrantHandler(func(username string, password string) (user interface{}) {
		return 1
	})

	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	values := make(url.Values)
	values.Add("client_id", "123")
	values.Add("client_secret", "s3cr3t")
	values.Add("grant_type", "password")
	s.testInvalidRequest(c, values)

	values.Add("username", "asdf")
	s.testInvalidRequest(c, values)
}

func (s *HttpTestSuite) TestTokenPasswordInvalidGrant(c *check.C) {
	PasswordGrantHandler(func(username string, password string) (user interface{}) {
		return nil
	})

	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	values := make(url.Values)
	values.Add("grant_type", "password")
	values.Add("client_id", "123")
	values.Add("client_secret", "s3cr3t")
	values.Add("username", "test_user")
	values.Add("password", "invalid")
	resp, err := http.PostForm(ts.URL, values)
	c.Assert(err, check.IsNil)
	c.Assert(resp.StatusCode, check.Equals, 400)

	body, err := io.ReadAll(resp.Body)
	c.Assert(err, check.IsNil)
	resp.Body.Close()

	e := Error{}
	err = json.Unmarshal(body, &e)
	c.Assert(err, check.IsNil)
	c.Assert(e.ErrorName, check.Equals, "invalid_grant")
}

func (s *HttpTestSuite) TestTokenPasswordUnsupportedGrant(c *check.C) {
	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	values := make(url.Values)
	values.Add("grant_type", "password")
	values.Add("client_id", "123")
	values.Add("client_secret", "s3cr3t")
	resp, err := http.PostForm(ts.URL, values)
	c.Assert(err, check.IsNil)
	c.Assert(resp.StatusCode, check.Equals, 400)

	body, err := io.ReadAll(resp.Body)
	c.Assert(err, check.IsNil)
	resp.Body.Close()

	e := Error{}
	err = json.Unmarshal(body, &e)
	c.Assert(err, check.IsNil)
	c.Assert(e.ErrorName, check.Equals, "unsupported_grant_type")
}

func (s *HttpTestSuite) TestTokenAuthorizationCode(c *check.C) {
	CodeHandler(func(code, redirect_uri string) (user interface{}) {
		return 1
	})

	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	values := make(url.Values)
	values.Add("client_id", "123")
	values.Add("client_secret", "s3cr3t")
	values.Add("grant_type", "authorization_code")
	values.Add("code", "test_code")
	values.Add("redirect_uri", "http://www.example.com")

	resp, _ := http.PostForm(ts.URL, values)
	c.Assert(resp.StatusCode, check.Equals, 200)

	body, err := io.ReadAll(resp.Body)
	c.Assert(err, check.IsNil)
	resp.Body.Close()

	token := new(TokenResponse)
	err = json.Unmarshal(body, token)
	c.Assert(err, check.IsNil)

	c.Assert(token.AccessToken, check.Equals, "test_access_token")
	c.Assert(token.RefreshToken, check.Equals, "test_refresh_token")
	c.Assert(token.ExpiresIn, check.Equals, 3600)
	c.Assert(token.TokenType, check.Equals, "Bearer")
}

func (s *HttpTestSuite) TestTokenAuthorizationCodeInvalidRequest(c *check.C) {
	CodeHandler(func(code, redirect_uri string) (user interface{}) {
		return 1
	})

	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	values := make(url.Values)
	values.Add("client_id", "123")
	values.Add("client_secret", "s3cr3t")
	values.Add("grant_type", "authorization_code")
	s.testInvalidRequest(c, values)

	values.Add("code", "asdf")
	s.testInvalidRequest(c, values)
}

func (s *HttpTestSuite) TestTokenAuthorizationCodeAccessDenied(c *check.C) {
	CodeHandler(func(code, redirect_uri string) (user interface{}) {
		return nil
	})

	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	values := make(url.Values)
	values.Add("client_id", "123")
	values.Add("client_secret", "s3cr3t")
	values.Add("grant_type", "authorization_code")
	values.Add("code", "test_code")
	values.Add("redirect_uri", "http://www.example.com")

	resp, _ := http.PostForm(ts.URL, values)
	c.Assert(resp.StatusCode, check.Equals, 400)

	body, err := io.ReadAll(resp.Body)
	c.Assert(err, check.IsNil)
	resp.Body.Close()

	e := Error{}
	err = json.Unmarshal(body, &e)
	c.Assert(err, check.IsNil)
	c.Assert(e.ErrorName, check.Equals, "access_denied")
}

func (s *HttpTestSuite) TestAuthValidate(c *check.C) {
	values := make(url.Values)
	values.Add("response_type", "code")
	values.Add("client_id", "123")
	values.Add("redirect_uri", "http://www.example.com")

	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	r, err := http.NewRequest("GET", ts.URL, nil)
	c.Assert(err, check.IsNil)
	r.URL.RawQuery = values.Encode()

	err = AuthValidate(r)
	c.Assert(err, check.IsNil)
}

func (s *HttpTestSuite) TestAuthValidateInvalidRequest(c *check.C) {
	values := make(url.Values)

	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	r, err := http.NewRequest("GET", ts.URL, nil)
	c.Assert(err, check.IsNil)
	r.URL.RawQuery = values.Encode()

	err = AuthValidate(r)
	c.Assert(err.(Error).ErrorName, check.Equals, "invalid_request")

	values.Add("response_type", "code")
	r.URL.RawQuery = values.Encode()
	err = AuthValidate(r)
	c.Assert(err.(Error).ErrorName, check.Equals, "invalid_request")

	values.Add("client_id", "123")
	r.URL.RawQuery = values.Encode()
	err = AuthValidate(r)
	c.Assert(err.(Error).ErrorName, check.Equals, "invalid_request")
}

func (s *HttpTestSuite) TestAuthValidateInvalidUri(c *check.C) {
	values := make(url.Values)
	values.Add("response_type", "code")
	values.Add("client_id", "123")
	values.Add("redirect_uri", "example.com")

	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	r, err := http.NewRequest("GET", ts.URL, nil)
	c.Assert(err, check.IsNil)
	r.URL.RawQuery = values.Encode()

	err = AuthValidate(r)
	c.Assert(err.(Error).ErrorName, check.Equals, "invalid_request")
}

func (s *HttpTestSuite) TestAuthValidateOobUrl(c *check.C) {
	values := make(url.Values)
	values.Add("response_type", "code")
	values.Add("client_id", "123")
	values.Add("redirect_uri", "urn:ietf:wg:oauth:2.0:oob")

	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	r, err := http.NewRequest("GET", ts.URL, nil)
	c.Assert(err, check.IsNil)
	r.URL.RawQuery = values.Encode()

	err = AuthValidate(r)
	c.Assert(err, check.IsNil)
}

func (s *HttpTestSuite) TestAuthSuccess(c *check.C) {
	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	values := make(url.Values)
	values.Add("state", "test_state")
	values.Add("redirect_uri", "http://www.example.com")

	w := httptest.NewRecorder()
	r, err := http.NewRequest("POST", ts.URL, nil)
	c.Assert(err, check.IsNil)

	AuthSuccess(w, r, "asdf")
	c.Assert(w.Code, check.Equals, 200)
	c.Assert(w.Header().Get("Location"), check.Equals, "http://www.example.com/")
}
