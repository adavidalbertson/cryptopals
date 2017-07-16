package ecb

import (
	crand "crypto/rand"
	"fmt"
	"github.com/adavidalbertson/cryptopals/padding"
	mrand "math/rand"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// UserProfile contains simple user data: email, uid, and role.
// Cryptopals Set 2, Challenge 13
// https://cryptopals.com/sets/2/challenges/13
type UserProfile struct {
	email string
	uid   int
	role  string
}

// ProfileMaker maintains a consistent key for encrypting profiles.
type ProfileMaker struct {
	key []byte
}

// NewProfileMaker generates a random key to encrypt profiles.
func NewProfileMaker() ProfileMaker {
	key := make([]byte, 16)
	_, _ = crand.Read(key)
	return ProfileMaker{key}
}

// ProfileFor creates an encrypted user token for the given email.
// It assigns a random three-digit uid and the "user" role.
// Cryptopals Set 2, Challenge 13
// https://cryptopals.com/sets/2/challenges/13
func (pm ProfileMaker) ProfileFor(email string) (token []byte, err error) {
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	profile := UserProfile{}

	// Don't allow other parameters in the email.
	profile.email = strings.Replace(strings.Replace(email, "&", "", -1), "=", "", -1)
	profile.uid = 100 + r.Intn(900)
	profile.role = "user"

	return Encrypt(padding.Pkcs7([]byte(WriteProfileToString(profile)), 16), pm.key)
}

// DecryptProfile decrypts the user data from a token.
// It prints a message if the user role is "admin".
// Cryptopals Set 2, Challenge 13
// https://cryptopals.com/sets/2/challenges/13
func (pm ProfileMaker) DecryptProfile(ciphertext []byte) (profile UserProfile, err error) {
	profilePlaintext, err := Decrypt(ciphertext, pm.key)
	if err != nil {
		return
	}

	profile, err = ParseStringToProfile(string(profilePlaintext))
	if err != nil {
		return
	}

	if profile.role == "admin" {
		fmt.Println("Congratulations, you are admin!")
	}

	return profile, err
}

// WriteProfileToString returns a string representing a url-encoded profile.
// Cryptopals Set 2, Challenge 13
// https://cryptopals.com/sets/2/challenges/13
func WriteProfileToString(p UserProfile) string {
	var pairs []string

	pairs = append(pairs, fmt.Sprintf("email=%s", p.email))
	pairs = append(pairs, fmt.Sprintf("uid=%d", p.uid))
	pairs = append(pairs, fmt.Sprintf("role=%s", p.role))

	return url.QueryEscape(strings.Join(pairs, "&"))
}

// ParseStringToProfile parses a url-encoded profile string into a profile object.
// Cryptopals Set 2, Challenge 13
// https://cryptopals.com/sets/2/challenges/13
func ParseStringToProfile(s string) (UserProfile, error) {
	out := UserProfile{"", -1, ""}
	s, err := url.QueryUnescape(s)
	if err != nil {
		return UserProfile{}, fmt.Errorf("Invalid query string")
	}

	pairs := strings.Split(s, "&")

	for _, pair := range pairs {
		p := strings.Split(pair, "=")
		if len(p) != 2 {
			return UserProfile{}, fmt.Errorf("Invalid key-value pair: %s", pair)
		}

		p[1] = strings.ToLower(strings.TrimSpace(p[1]))

		switch p[0] {
		case "email":
			out.email = p[1]
		case "uid":
			uid, err := strconv.Atoi(p[1])
			if err != nil {
				return UserProfile{}, fmt.Errorf("Invalid uid: %s", p[1])
			}

			out.uid = uid
		case "role":
			out.role = p[1]
		}
	}

	if len(out.email) == 0 || out.uid == -1 || len(out.role) == 0 {
		return UserProfile{}, fmt.Errorf("Incomplete profile: %s", s)
	}
	return out, nil
}
