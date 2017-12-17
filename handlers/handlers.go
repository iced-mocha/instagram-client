package handlers

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	"github.com/gorilla/mux"
	"github.com/iced-mocha/instagram-client/config"
)

type CoreHandler struct {
	client *http.Client
	conf   *config.Config
}

type InstagramAuthResponse struct {
	Token string        `json:"access_token"`
	User  instagramUser `json:"user"`
}

type instagramUser struct {
	Username       string `json:"username"`
	DisplayName    string `json:"full_name"`
	ProfilePicture string `json:"profile_picture"`
}

func New(conf *config.Config) (*CoreHandler, error) {
	if conf == nil {
		return nil, errors.New("must initialize handler with non-nil config")
	}

	caCert, err := ioutil.ReadFile("/usr/local/etc/ssl/certs/core.crt")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
	}

	h := &CoreHandler{client: client, conf: conf}
	return h, nil
}

type AuthRequest struct {
	Token  string `json:"token"`
	Secret string `json:"secret"`
}

/*
func (api *CoreHandler) GetPosts(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["userID"]
	log.Printf("Received request to GetPosts for user %v", username)
	pageToken := r.FormValue("continue")
	log.Printf("Received pagetoken %v in GetPosts", pageToken)

	contents, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("Unable to read request body in GetPosts: %v", err)
		http.Error(w, "error reading request body", http.StatusInternalServerError)
		return
	}

	authRequest := &AuthRequest{}
	if err := json.Unmarshal(contents, authRequest); err != nil {
		log.Printf("Unable to marshal request body in GetPosts: %v", err)
		http.Error(w, "error parsing request body", http.StatusInternalServerError)
		return
	}

	pageMap := make(map[string][]byte)
	// Check our cache to avoid being ratelimited
	if pageMapI, exists := api.cache.Get(username); exists {
		// TODO fix this
		pageMap, _ = pageMapI.(map[string][]byte)

		if contents, exists := pageMap[pageToken]; exists {
			// We expect our posts to be stored as byte array
			log.Printf("Found requested page %v in cache", pageToken)
			w.Write(contents)
			return
		}
	}

	// Add values for twitter api
	form := make(url.Values)
	form["count"] = []string{"20"}
	form["tweet_mode"] = []string{"extended"}
	if pageToken != "" {
		form["max_id"] = []string{pageToken}
	}

	creds := &oauth.Credentials{Token: authRequest.Token, Secret: authRequest.Secret}
	resp, err := oauthClient.Get(nil, creds, "https://api.twitter.com/1.1/statuses/home_timeline.json", form)
	if err != nil {
		log.Printf("Unable to complete request to twitter in GetPosts: %v", err)
		http.Error(w, "error completing request", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	contents, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Unable to read response body from twitter in GetPosts: %v", err)
		http.Error(w, "error reading response body from twitter", http.StatusInternalServerError)
		return
	}

	// We also need to marshal our contents to get the additional twitter meta data
	// Metatext will be a map of tweet id -> json string of tweet meta
	metaMap := meta.ParseMeta(contents)

	// First Marshal response in list of Twitter Posts
	twitterPosts := make([]tweet, 0)
	err = json.Unmarshal(contents, &twitterPosts)
	if err != nil {
		log.Printf("Unable to unmarshal body from twitter in GetPosts: %v", err)
		http.Error(w, "error unmarshaling response body from twitter", http.StatusInternalServerError)
		return
	}

	posts := []models.Post{}
	var maxID int64
	maxID = 1<<63 - 1

	for _, tweet := range twitterPosts {
		t, err := time.Parse(time.RubyDate, tweet.Timestamp)
		if err != nil {
			log.Printf("Unable to parse timestamp for tweet: %v - %v", tweet.ID, err)
		}

		// For pagination
		if tweet.IDNum < maxID {
			maxID = tweet.IDNum
		}

		text := tweet.Text
		imgURL := tweet.User.ProfileImageURL
		// Kind of hack to avoid making models struct too specific
		if tweet.RetweetStatus.Text != "" {
			text = "RT @" + tweet.RetweetStatus.User.Handle + ": " + tweet.RetweetStatus.Text
			imgURL = tweet.RetweetStatus.User.ProfileImageURL
		}

		favourites := tweet.Favourites
		if tweet.RetweetStatus.Favourites > favourites {
			favourites = tweet.RetweetStatus.Favourites
		}

		generic := models.Post{
			ID:          tweet.ID,
			Date:        t,
			Author:      tweet.User.Handle,
			DisplayName: tweet.User.Name,
			URL:         "https://twitter.com/" + tweet.User.Handle + "/status/" + tweet.ID,
			Platform:    "twitter",
			Score:       favourites + tweet.Retweets,
			Retweets:    tweet.Retweets,
			Favourites:  favourites,
			Title:       text,
			ProfileImg:  imgURL,
			Meta:        metaMap[tweet.ID],
		}
		posts = append(posts, generic)
	}

	nextURI := fmt.Sprintf("/v1/%v/posts?continue=%v", username, maxID-1)
	log.Printf("Constructed next URI: %v", nextURI)
	clientResp := models.ClientResp{
		Posts:   posts,
		NextURL: nextURI,
	}

	contents, err = json.Marshal(clientResp)
	if err != nil {
		log.Printf("Unable to marshal posts into json: %v", err)
		http.Error(w, "error marshaling posts into json", http.StatusInternalServerError)
		return
	}

	// Update our value into the cache
	pageMap[pageToken] = contents
	api.cache.Set(username, pageMap, gocache.DefaultExpiration)
	w.Write(contents)
}*/

/*
func (api *CoreHandler) PostTwitterSecrets(token, secret, userID, twitterUsername string) {
	// Post the bearer token to be saved in core
	log.Printf("Preparing to store twitter account in core for user: %v", userID)
	// TODO: Get twitter handler redditUsername, err := api.GetIdentity(bearerToken)

	jsonStr := []byte(fmt.Sprintf(`{ "type": "twitter", "username": "%v", "token": "%v", "secret": "%v"}`, twitterUsername, token, secret))
	req, err := http.NewRequest(http.MethodPost, api.conf.CoreURL+"/v1/users/"+userID+"/authorize/twitter", bytes.NewBuffer(jsonStr))
	if err != nil {
		log.Printf("Unable to post bearer token for user: %v - %v", userID, err)
		return
	}

	// TODO: add retry logic
	resp, err := api.client.Do(req)
	if err != nil {
		log.Printf("Unable to complete request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Could not post reddit data to core: %v", err)
	}
}*/

// Exchanges the given valid code for a token from Instagram
func (api *CoreHandler) requestToken(code string) (*InstagramAuthResponse, error) {
	vals := make(url.Values)
	vals.Set("grant_type", "authorization_code")
	vals.Set("code", code)
	vals.Set("redirect_uri", api.conf.RedirectURI)
	vals.Set("client_id", api.conf.InstagramClientID)
	vals.Set("client_secret", api.conf.InstagramSecret)

	resp, err := http.PostForm("https://api.instagram.com/oauth/access_token", vals)
	if err != nil {
		log.Printf("Unable to complate request for bearer token: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Unable to read response body: %v", err)
		return nil, err
	}

	log.Printf("Received the following body from instagram: %v", string(body))

	// Unmarshall response containing our bearer token
	authResponse := &InstagramAuthResponse{}
	err = json.Unmarshal(body, authResponse)
	if err != nil {
		log.Printf("Unable to parse response from instagram: %v", err)
		return nil, err
	}

	return authResponse, nil
}

// We get redirected back here after attempt to retrieve an oauth code from Instagram
func (api *CoreHandler) AuthorizeCallback(w http.ResponseWriter, r *http.Request) {
	log.Println("Reaceived callback from Instagram oauth")

	// Get the query string
	vals := r.URL.Query()

	// If "error" is not an empty string we have not received our access code
	// This is error param is specified by the Reddit API
	if val, ok := vals["error"]; ok {
		if len(val) != 0 {
			log.Printf("Did not receive authorization. Error: %v\n", vals["error"][0])
			// This is the case where the user likely denied us access
			// TODO: should redirect back to appropriate page in front-end
			return
		}
	}

	var instaAuth *InstagramAuthResponse
	var err error
	// Make sure the code exists
	if len(vals["code"]) > 0 {
		// Now request bearer token using the code we received
		instaAuth, err = api.requestToken(vals["code"][0])
		if err != nil {
			log.Printf("Unable to receive bearer token: %v\n", err)
			return
		}
	}

	log.Printf("Received the following auth from instagram: %+v", *instaAuth)

	// Post code back to core async as the rest is not dependant on this -- vals["state"] should be userID
	go api.postInstaAuth(instaAuth, vals["state"][0])

	// Redirect to frontend
	http.Redirect(w, r, api.conf.FrontendURL, http.StatusMovedPermanently)
}

func (api *CoreHandler) postInstaAuth(auth *InstagramAuthResponse, username string) {
	// Post the token and insta username to be saved in core
	log.Printf("Preparing to store instagram account in core for user: %v", username)

	jsonStr := []byte(fmt.Sprintf(`{ "type": "instagram", "username": "%v", "token": "%v"}`, auth.User.Username, auth.Token))
	req, err := http.NewRequest(http.MethodPost, api.conf.CoreURL+"/v1/users/"+username+"/authorize/instagram", bytes.NewBuffer(jsonStr))
	if err != nil {
		log.Printf("Unable to post bearer token for user: %v - %v", username, err)
		return
	}

	// TODO: add retry logic
	resp, err := api.client.Do(req)
	if err != nil {
		log.Printf("Unable to complete request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Could not post instagram data to core: %v", err)
	}
}

// This function initiates a request to Instagram to authorize via oauth
// Usually we are redirect here from core
// GET /v1/{userID}/authorize
func (api *CoreHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["userID"]
	url := fmt.Sprintf("https://api.instagram.com/oauth/authorize/?client_id=%v&redirect_uri=%v&response_type=code&state=%v",
		api.conf.InstagramClientID, api.conf.RedirectURI, username)

	// Redirect to instagrams auth page
	http.Redirect(w, r, url, 302)
}
