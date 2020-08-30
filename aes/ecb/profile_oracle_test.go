package ecb

import (
	"reflect"
	"testing"
)

func TestParseStringToProfile(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name           string
		args           args
		want           UserProfile
		wantErr        bool
		wantErrMessage string
	}{
		{"challenge_13", args{"email=foo@bar.com&uid=10&role=user"}, UserProfile{"foo@bar.com", 10, "user"}, false, ""},
		{"invalid_query", args{"email=foo@bar.%com&uid=10&role=user"}, UserProfile{}, true, "Invalid query string"},
		{"invalid_uid", args{"email=foo@bar.com&uid=ten&role=user"}, UserProfile{}, true, "Invalid uid: ten"},
		{"missing_email", args{"uid=10&role=user"}, UserProfile{}, true, "Incomplete profile: uid=10&role=user"},
		{"missing_uid", args{"email=foo@bar.com&role=user"}, UserProfile{}, true, "Incomplete profile: email=foo@bar.com&role=user"},
		{"missing_role", args{"email=foo@bar.com&uid=10"}, UserProfile{}, true, "Incomplete profile: email=foo@bar.com&uid=10"},
		{"empty_email", args{"email=&uid=10&role=user"}, UserProfile{}, true, "Incomplete profile: email=&uid=10&role=user"},
		{"empty_uid", args{"email=foo@bar.com&uid=&role=user"}, UserProfile{}, true, "Invalid uid: "},
		{"empty_role", args{"email=foo@bar.com&uid=10&role="}, UserProfile{}, true, "Incomplete profile: email=foo@bar.com&uid=10&role="},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseStringToProfile(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseStringToProfile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if (err != nil) && (err.Error() != tt.wantErrMessage) {
				t.Errorf("ParseStringToProfile() error message = %v, wantErrMessage %v", err.Error(), tt.wantErrMessage)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseStringToProfile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWriteProfileToString(t *testing.T) {
	type args struct {
		p UserProfile
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"challenge_13", args{UserProfile{"foo@bar.com", 10, "user"}}, "email=foo@bar.com&uid=10&role=user"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := WriteProfileToString(tt.args.p); got != tt.want {
				t.Errorf("WriteProfileToString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProfileMaker_profileFor(t *testing.T) {
	type args struct {
		email string
	}
	tests := []struct {
		name        string
		args        args
		wantProfile UserProfile
	}{
		{
			"challenge_13",
			args{"foo@bar.com"},
			UserProfile{"foo@bar.com", 0, "user"},
		},
		{
			"challenge_13_hack_attempt",
			args{"foo@bar.com&role=admin"},
			UserProfile{"foo@bar.comroleadmin", 0, "user"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := NewProfileMaker()
			gotProfile := pm.profileFor(tt.args.email)
			if gotProfile.email != tt.wantProfile.email {
				t.Errorf("ProfileMaker.profileFor() email = %v, want %v", gotProfile.email, tt.wantProfile.email)
			}
			if gotProfile.role != tt.wantProfile.role {
				t.Errorf("ProfileMaker.profileFor() role = %v, want %v", gotProfile.role, tt.wantProfile.role)
			}
		})
	}
}
