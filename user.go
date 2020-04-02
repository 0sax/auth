package auth

import (
	"cloud.google.com/go/firestore"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"strconv"
)

// User is a holder struct for carrying user details to and from various functions as needed
type User struct {
	FirstName string `firestore:"firstName,omitempty"`
	LastName  string `firestore:"lastName,omitempty"`
	Email     string `firestore:"email,omitempty"`
	Password  string `firestore:"password,omitempty"`
	UserID    int    `firestore:"userID,omitempty"`
	Role      string `firestore:"role,omitempty"`
	Approved  bool   `firestore:"approved,omitempty"`
}

// Create creates a new user and logs to the database
func (u *User) Create() error {

	_, err := u.getUserSnapshot()
	if err != nil && err.(*AuthError).errType != ErrNoUser {
		return errors.New("user already exists")
	}

	// 1. Generate Password hash
	pass, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		return errors.New("Password Encryption failed" + err.Error())
	}

	u.Password = string(pass)
	u.Approved = false

	// 2. Add User
	_, _, err = av.DBName.Collection("users").Add(av.GCContext, u)
	if err != nil {
		return err
	}

	return nil
}

//getUserSnapshot pulls up the firestore.DocumentSnapshot for User u
func (u *User) getUserSnapshot() (*firestore.DocumentSnapshot, error) {
	if u.Email == "" {
		return nil, &AuthError{msg: "please provide an email address",
			errType: ErrNoEmail}
	}

	usr, err := av.DBName.Collection("users").Where("email", "==", u.Email).
		Documents(av.GCContext).GetAll()
	if err != nil {
		return nil, &AuthError{
			msg:     "User " + u.Email + "does not exist",
			errType: ErrNoUser,
		}
	}

	if len(usr) > 1 {
		return nil, &AuthError{
			msg: "there are " + strconv.Itoa(len(usr)) +
				" users with this email address, contact admin",
			errType: ErrDuplicateUser,
		}
	}

	return usr[0], nil

}

// Edit Changes user details to those defined in the User struct
// All non-zero values will overwrite existing values
func (u User) Edit() error {
	usr, err := u.getUserSnapshot()
	if err != nil {
		return err
	}
	_, err = usr.Ref.Set(av.GCContext, u, firestore.Merge())
	if err != nil {
		return err
	}
	return nil
}

// UpdateFromSession uses the GetSession function to
// ...get the session details, and parses the returned session
// to a User struct
func (u *User) UpdateFromSession(s string) error {
	m, err := GetSession(s)
	if err != nil {
		return errors.New("Unable to get user details because: " + err.Error())
	}
	u.FirstName = m.FirstName
	u.LastName = m.LastName
	u.Email = m.Email
	u.Role = m.Role
	return nil
}

// SignIn confirms that the entered User credentials (email and password)
// match what is in the Firestore, creates a session for the user on the server,
// and returns a cookie containing the session token
func (u *User) SignIn() (*http.Cookie, error) {
	if u.Email == "" {
		return nil, &AuthError{msg: "please provide an email address",
			errType: ErrNoEmail}
	}
	if u.Password == "" {
		return nil, &AuthError{msg: "please provide an email address",
			errType: ErrNoPassword}
	}
	pw := u.Password

	// check for user
	usr, err := u.getUserSnapshot()
	if err != nil {
		return nil, err
	}

	err = usr.DataTo(&u)
	if err != nil {
		return nil, &AuthError{
			msg:      "error parsing user details to user struct: " + err.Error(),
			errType:  ErrParseError,
			ancestor: err,
		}
	}

	if u.Approved != true {
		return nil, &AuthError{
			msg:     "user account not yet approved",
			errType: ErrUserNotApproved,
		}
	}

	//compare password
	err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(pw))
	if err != nil {
		return nil, &AuthError{
			msg:      "Wrong Password",
			errType:  ErrWrongPassword,
			ancestor: err,
		}
	}

	// create session
	c, err := CreateSession(u, av.CookieName, av.SessionLife)
	if err != nil {
		fmt.Println(err)
		return nil, &AuthError{
			msg:      "login error, contact admin",
			errType:  ErrNoSessionCreated,
			ancestor: err,
		}
	}

	return c, nil
}
