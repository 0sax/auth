// auth handles session/token based authentication on firebase
// to initialise package an InitAuthVariables struct must be created and the initialized
// in main
package auth

import (
	"cloud.google.com/go/firestore"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/status"
	"html/template"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// InitAuthVariables is a holder for the auth initialization variables
type InitAuthVariables struct {
	CookieName          string            // used to store user sessions
	FlashCookieName     string            // Used to display flashes to the user
	DBName              *firestore.Client // Firestore client connection
	RedirectOnSignIn    string            // Route user is redirected to, on Sign in
	redirectIfLoggedout string            // Route user is redirected to, on Logout
	redirectIfNoRight   string            // Route user is redirected to, if they lack permission
	SessionLife         string            //secondsst, string
	GcloudCtx           context.Context   // gcloud context
}

var (
	Av          InitAuthVariables
	sessionLife int //secondsst, string
	err1        error
)

// Init initializes the package based on variables defined in the
// InitAuthVariables struct
func (iav InitAuthVariables) Init() {
	Av = iav
	sessionLife, err1 = strconv.Atoi(iav.SessionLife) // SessionLife
	if err1 != nil {
		fmt.Println("Error getting session life", err1)
	}
}

// Session represents a user session stored on the database
type Session struct {
	Email      string    //`firestore:"email"`
	ExpiryDate time.Time //`firestore:"expireDate"`
	FirstName  string    //`firestore:"firstName"`
	LastName   string    //`firestore:"lastName"`
	Role       string    //`firestore:"roles"`
}

// CanAccess checks if a user's role is one of those listed
// in the roles array. This is used in tandem with the authMiddleware
// function to restrict access to certain handlers
func (s *Session) CanAccess(roles []string) bool {
	for _, x := range roles {
		if s.Role == x {
			return true
		}
	}

	return false
}

type User struct {
	FirstName string `json:"FirstName" firestore:"firstName"`
	LastName  string `firestore:"lastName"`
	Email     string `firestore:"email"`
	Password  string `firestore:"password"`
	UserID    int
	Role      string `firestore:"role"`
	Approved  bool   `firestore:"approved"`
}

// GetSessionUser uses the GetSessionDetails function to
// ...get the session details, and parses the returned session
// to a User struct
func (u *User) GetSessionUser(s string) {
	m, err := GetSessionDetails(s)
	if err != nil {
		fmt.Println("Error getting session user")
		return
	}
	u.FirstName = m.FirstName
	u.LastName = m.LastName
	u.Email = m.Email
}

// SignIn confirms that the entered User credentials (email and password)
// match what is in the Firestore, creates a session for the user on the server,
// and returns a cookie containing the session token
func (u User) SignIn() (*http.Cookie, error) {
	pw := u.Password

	// check for user
	usr, err := Av.DBName.Collection("users").Where("email", "==", u.Email).
		Where("approved", "==", true).Documents(Av.GcloudCtx).GetAll()
	if err != nil {
		return nil, errors.New("user " + u.Email + " does not exist")
	}

	err = usr[0].DataTo(&u)
	if err != nil {
		return nil, errors.New("error parsing user details to user struct: " + err.Error())
	}

	//compare password
	err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(pw))
	if err != nil {
		return nil, errors.New("wrong password")
	}

	// create session
	c, err := CreateSession(u, Av.CookieName, sessionLife)
	if err != nil {
		fmt.Println(err)
		return nil, errors.New("Login Error, Contact Admin")
	}

	return c, nil
}

//func (u *User) assignUserRoles() error {
//
//	resp, err := Av.DBName.Query(
//		`SELECT role_id FROM many_users_have_many_roles
//				WHERE email = $1`, u.Email)
//	if err != nil {
//		return err
//	}
//
//	for resp.Next() {
//		var i int
//		resp.Scan(&i)
//		u.Roles = append(u.Roles, i)
//	}
//	return nil
//}

type itemAndTotals struct {
	Items interface{}
	Total int
}

type PageVariables struct {
	BadFlash       string
	GoodFlash      string
	Data           interface{}
	Data2          interface{}
	ItemsAndTotals itemAndTotals
	User           User
	Title          string
	CompanyName    string
	TopFlash       struct {
		Bad  string
		Good string
	}
}

// AddFlash Adds a flash to the pagevariables struct to be rendered immediately
// Overrides any flash already in the template
func (pv *PageVariables) AddFlash(f string) {

	if strings.HasPrefix(f, "Warning:") {
		ns := strings.TrimLeft(f, "Warning:")
		pv.BadFlash = ns
	} else {
		pv.GoodFlash = f
	}

}

// 13. Create New User
func CreateUser(u User) error {

	//Check if user already exists
	usrs := Av.DBName.Collection("users").Where("email", "==", u.Email).Documents(Av.GcloudCtx)
	for {
		_, err := usrs.Next()
		if err != nil {
			break
		}
		if err == nil { // if username is found, return a username found error
			return errors.New("User already exists")
		}
	}

	// 1. Generate Password hash
	pass, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		return errors.New("Password Encryption failed" + err.Error())
	}

	u.Password = string(pass)

	// 2. Add User
	_, _, err = Av.DBName.Collection("users").Add(Av.GcloudCtx, u)

	if err != nil {
		return err
	}

	return nil

}

// Sign In
func SignIn(w http.ResponseWriter, r *http.Request) {
	// if GET, Check if a session already exists...
	if r.Method != http.MethodPost {
		c, err := r.Cookie(Av.CookieName)
		if err == nil {
			_, done2 := isUserNameInCache(c.Value, w, r)
			// .. if session exists redirect to dashboard
			if done2 {
				http.Redirect(w, r, Av.RedirectOnSignIn, http.StatusFound)
				return
			}
		}
		// ... if session doesn't exist render login page
		pv := PageVariables{Title: "788 Kollektor"}
		pv.AddFlash(GetFlash(w, r, Av.CookieName))
		t := template.Must(template.ParseFiles("templates/a.html",
			"templates/signin.html"))
		err = t.Execute(w, pv)
		if err != nil {
			fmt.Println("Couldn't parse template", err)
			return
		}
		return
	}

	// If post...
	r.ParseForm()
	u := User{Email: r.FormValue("Email"), Password: r.FormValue("Password")}
	// create session
	c, err := u.SignIn()
	if err != nil {
		fmt.Println("Error finding user:", err)
		SetFlash(w, "Warning:Server error code zambezi")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	//Set Cookie
	http.SetCookie(w, c)
	fmt.Println("Logged In Successfully")
	http.Redirect(w, r, Av.RedirectOnSignIn, http.StatusFound)
	return
}

func CreateSession(user User, ckName string, life int) (*http.Cookie, error) {
	////  Generate a token
	sessionToken := RandomString(45)
	expiryDate := time.Now().Add(time.Duration(life) * time.Second)

	//// Write to DB
	_, err := Av.DBName.Collection("sessions").Doc(sessionToken).
		Set(Av.GcloudCtx, map[string]interface{}{
			"email":      user.Email,
			"firstName":  user.FirstName,
			"lastName":   user.LastName,
			"role":       user.Role,
			"expiryDate": expiryDate,
		})

	if err != nil {
		return nil, err
	}

	// Set Cookie
	return &http.Cookie{
		Name:    ckName,
		Value:   sessionToken,
		Expires: expiryDate,
	}, nil
}

func SignOut(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(Av.CookieName)
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Println("Client didn't send a cookie named:", Av.CookieName, err)
			return
		}
		fmt.Println("Didn't work for other reason:", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	sessionToken := c.Value

	// NUNU
	if err = KillSession(sessionToken); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Println("Couldn't kill Session from server", err)
		return
	}

	// Wipe client cookie
	http.SetCookie(w, &http.Cookie{Name: Av.CookieName, Value: ""})
	http.Redirect(w, r, "/", http.StatusFound)
	return
}

func KillSession(sessionToken string) error {
	_, err := Av.DBName.Collection("sessions").Doc(sessionToken).Delete(Av.GcloudCtx)
	if err != nil {
		return err
	}

	return nil
}

func AuthMiddleware(next func(w http.ResponseWriter, r *http.Request, userToken string), roles []string) http.Handler {

	/*
			      todo adjust response based on conditions
		1. Session doesn't exist, redirect to log in page
			2. Sesion exists but role does not, redirect to no access page
	*/
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {

			c, err := r.Cookie(Av.CookieName)
			if err != nil {
				if err == http.ErrNoCookie {
					fmt.Println("Client didn't send a cookie:", err)
					http.Redirect(w, r, "/", http.StatusUnauthorized)
					return
				}
				fmt.Println("Didn't work for other reason:", err)
				http.Redirect(w, r, "/", http.StatusUnauthorized)
				return
			}
			sessionToken := c.Value
			err, done2 := isUserNameInCache(sessionToken, w, r)
			if !done2 {
				fmt.Println("session search error:", err)
				http.Redirect(w, r, "/", http.StatusUnauthorized)
				return
			}

			// ROLES
			// determine User role
			s, err := GetSessionDetails(sessionToken)
			if err != nil {
				fmt.Println("error if any:", err)
				http.Redirect(w, r, "/", http.StatusForbidden)
				return
			}

			//2. Learn how to store the User role in redis during sign in and pull it from there on check*/
			// check if it exists in role
			if s.CanAccess(roles) != true {
				fmt.Println("User does not have the necessary privileges to view this page")
				w.WriteHeader(http.StatusForbidden)
				return
			}

			next(w, r, sessionToken)

		})

}

func isUserNameInCache(sessionToken string, w http.ResponseWriter, r *http.Request) (error, bool) {

	//1. Check if it's in the cache
	s, err := Av.DBName.Collection("sessions").Doc(sessionToken).
		Get(Av.GcloudCtx)
	if err != nil {
		return errors.New("error querying db for session: " + status.Code(err).String()), false
	}
	// return false if session doesn't exist
	if s.Exists() == false {
		return errors.New("no Session with that token"), false
	}

	var ss Session
	// delete if it has expired
	if err := s.DataTo(&ss); err != nil {
		return errors.New("couldn't parse session to struct"), false
	}
	if ss.ExpiryDate.Before(time.Now()) {
		// Delete session
		_, err := s.Ref.Delete(Av.GcloudCtx)
		if err != nil {
			return errors.New("session expired, failed to delete"), false
		}
		return errors.New("session expired, deleted"), false
	}
	return nil, true
}

func SetFlash(w http.ResponseWriter, value string) {
	c := &http.Cookie{Name: Av.FlashCookieName,
		Value: base64.URLEncoding.EncodeToString([]byte(value))}
	http.SetCookie(w, c)
}

func GetFlash(w http.ResponseWriter, r *http.Request, name string) string {

	c, err := r.Cookie(name)
	if err != nil {
		switch err {
		case http.ErrNoCookie:
			return ""
		default:
			fmt.Println("Error getting flash cookie")
			return "Internal Error 106"
		}
	}

	value, err := base64.URLEncoding.DecodeString(c.Value)
	if err != nil {
		fmt.Println("Error decoding flash cookie value")
		return "Internal Error 107"
	}
	dc := &http.Cookie{Name: name, MaxAge: -1, Expires: time.Unix(1, 0)}
	http.SetCookie(w, dc)
	return string(value)
}

func randomInt(min, max int) int {
	return min + rand.Intn(max-min)
}

// Generate a random string of A-Z chars with len = l
func RandomString(len int) string {
	bytes := make([]byte, len)
	for i := 0; i < len; i++ {
		bytes[i] = byte(randomInt(65, 90))
	}
	return string(bytes)
}

// GetSessionDetails checks the database to see if
// there is a valid session with the provided token (s)
// and returns the session if so
func GetSessionDetails(sT string) (Session, error) {

	s, err := Av.DBName.Collection("sessions").Doc(sT).Get(Av.GcloudCtx)
	if err != nil {
		return Session{}, errors.New("error querying db for Session: " + status.Code(err).String())
	}

	if s.Exists() != true {
		return Session{}, errors.New("Session doesn't exist: ")
	}

	var se Session
	err = s.DataTo(&se)
	if err != nil {
		return Session{}, errors.New("error parsing Session to struct: ")
	}
	return se, nil
}

//Deprecated Functions
func convertStringSlicetoInterface(ss []string) []interface{} {

	s := make([]interface{}, len(ss))
	for i, v := range ss {
		s[i] = v
	}

	return s
}
func getKeysMatchingPattern(p string) ([]string, error) {

	//c := "0"
	var kk []string
	//
	//resp, err := redis.Values(Cache.Do("SCAN", c, "MATCH", p+"*"))
	//if err != nil {
	//	fmt.Println("Error doing scan1", err)
	//	return nil, err
	//}
	//if resp[1] != nil {
	//	kk = convertbyteSlicetoStringlice(resp[1].([]interface{}))
	//}
	//
	//c = string(resp[0].([]uint8))
	//
	//for c != "0" {
	//
	//	resp, err := redis.Values(Cache.Do("SCAN", c, "MATCH", p+"*"))
	//	if err != nil {
	//		fmt.Println("Error doing scan2", err)
	//		return nil, err
	//	}
	//	if resp[1] != nil {
	//		kk = append(kk, convertbyteSlicetoStringlice(resp[1].([]interface{}))...)
	//	}
	//	c = string(resp[0].([]uint8))
	//}

	return kk, nil
}
func DoesXHaveY(x, y []string) bool {

	var ct int

	for n, a := range y {
		for _, b := range x {
			if a == b {
				ct++
				break
			}
		}
		if ct != n+1 {
			return false
		}
	}

	if ct == len(y) {
		return true
	}

	return false

}
func convertbyteSlicetoStringlice(bs []interface{}) []string {
	var ss []string
	for _, x := range bs {
		ss = append(ss, string(x.([]byte)))
	}
	return ss
}
func pushRoles(rr []int, k string) error {
	//	for _, x := range rr {
	//		_, err := Cache.Do("RPUSH", k, strconv.Itoa(x)) //roles
	//		if err != nil {
	//			return err
	//		}
	//	}
	return nil
}
func convertRolestoInt(rs []string) ([]int, error) {
	var roles []int
	//	for _, r := range rs {
	//		ri, err := strconv.Atoi(r)
	//		if err != nil {
	//			return nil, err
	//		}
	//		roles = append(roles, ri)
	//	}
	return roles, nil
}
