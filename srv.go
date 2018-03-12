package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type access struct {
	Token string
}

type response struct {
	Message string
}

type user struct {
	Token        string
	UID          string
	ExpiresAt    time.Time `bson:"expires_at"`
	PasswordHash string    `bson:"password_hash"`
}

func main() {

	http.HandleFunc("/", greet)
	err := http.ListenAndServeTLS(":8001", "/etc/letsencrypt/live/supriya.tech/fullchain.pem", "/etc/letsencrypt/live/supriya.tech/privkey.pem", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
	fmt.Println("LISTEN AND SERVE OK")
}

// POST handler
func greet(w http.ResponseWriter, r *http.Request) {
	var a access
	var u user
	w.Header().Set("Content-type", "application/json")
	// Allow requests originating only from the flask app
	w.Header().Set("Access-Control-Allow-Origin", "https://supriya.tech")
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println(body)
	}

	if json.Unmarshal(body, &a) != nil {
		fmt.Println("Unmarshall Error")
	}

	session, err := mgo.Dial("localhost:27017")
	if err != nil {
		fmt.Println("Couldnot connect to the DB")
	}
	c := session.DB("auth").C("users")
	session.SetMode(mgo.Monotonic, true)
	err = c.Find(bson.M{"token": a.Token}).One(&u)
	if err != nil {
		http.Error(w, "user not found", 404)
	}

	// Validate session using the token
	now := bson.Now()
	expired := u.ExpiresAt
	delta := expired.Sub(now)
	if delta < 0 {
		http.Error(w, "session expired", 401)
	}

	resp := response{
		Message: fmt.Sprintf("Gopher says, Hello! %v", u.UID),
	}

	b, err := json.Marshal(resp)
	if err != nil {
		fmt.Println("Marshalling Error")
	}
	w.Write(b)

	if err != nil {
		panic("Couldnot open a connection to the DB")
	}
	defer session.Close()
}
