package auth

import (
	"errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// Session represents a user session stored on the database
type Session struct {
	Email      string    //`firestore:"email"`
	ExpiryDate time.Time //`firestore:"expiryDate"`
	FirstName  string    //`firestore:"firstName"`
	LastName   string    //`firestore:"lastName"`
	Role       string    //`firestore:"roles"`
}

// CanAccess checks if a user's role is one of those listed
// in the roles slice. This is used in tandem with the authMiddleware
// function to restrict access to certain handlers
func (s *Session) CanAccess(roles []string) bool {
	for _, x := range roles {
		if s.Role == x {
			return true
		}
	}
	return false
}

// CreateSession creates a new session, writes this to the DB and returns a cookie
func CreateSession(user *User, ckName string, life int) (*http.Cookie, error) {
	////  Generate a token
	sessionToken := randomString(45)
	expiryDate := time.Now().Add(time.Duration(life) * time.Second)

	//// Write to DB
	_, err := av.DBName.Collection("sessions").Doc(sessionToken).
		Set(av.GCContext, map[string]interface{}{
			"email":      user.Email,
			"firstName":  user.FirstName,
			"lastName":   user.LastName,
			"role":       user.Role,
			"expiryDate": expiryDate,
		})

	if err != nil {
		return nil, &authError{
			msg:     "error creating session: " + err.Error(),
			errType: ErrNoSessionCreated,
		}
	}

	// Set Cookie
	return &http.Cookie{
		Name:    ckName,
		Value:   sessionToken,
		Expires: expiryDate,
	}, nil
}

// KillSession deletes a session from the database
func KillSession(sessionToken string) error {
	_, err := av.DBName.Collection("sessions").Doc(sessionToken).Delete(av.GCContext)
	if err != nil {
		return err
	}

	return nil
}

// randomString generates a random string of A-Z chars with len = l
func randomString(l int) string {
	rand.Seed(time.Now().UnixNano())

	time.Sleep(time.Nanosecond)

	chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz" +
		"0123456789")
	length := l
	var b strings.Builder
	for i := 0; i < length; i++ {
		b.WriteRune(chars[rand.Intn(len(chars))])
	}

	return b.String()

}

// GetSession checks the database to see if
// there is a valid session with the provided token (s)
// and returns the session if so
func GetSession(sT string) (*Session, error) {
	// Dev Note: A valid session and an error must never be returned together
	// There can be only one!

	//1. Get session
	s, err := av.DBName.Collection("sessions").Doc(sT).Get(av.GCContext)
	if err != nil {
		if status.Code(err) == codes.NotFound { // if session doesn't exist
			return nil, &authError{
				msg:      "session doesn't exist",
				errType:  ErrNoSession,
				ancestor: err,
			}
		} else { // if any other kind of error is returned
			return nil, err
		}
	}

	// parse session to struct
	var se *Session
	err = s.DataTo(&se)
	if err != nil {
		return nil, errors.New("error parsing Session to struct: ")
	}

	// Check if session has expired
	if se.ExpiryDate.Before(time.Now()) {
		// Delete session
		_, err := s.Ref.Delete(av.GCContext)
		if err != nil {
			return nil, errors.New("session expired, failed to delete")
		}
		return nil, errors.New("session expired, deleted")
	}

	return se, nil
}

// DeleteDeadSessions deletes all the expired sessions from the FireStore DB
func DeleteDeadSessions() error {
	// get all dead sessions
	q := av.DBName.Collection("sessions").
		Where("expiryDate", "<", time.Now()).Documents(av.GCContext)
	// delete them
	x, err := q.GetAll()
	if err != nil {
		return err
	}
	for _, ds := range x {
		_, err = ds.Ref.Delete(av.GCContext)
		if err != nil {
			return err
		}
	}
	return nil
}
