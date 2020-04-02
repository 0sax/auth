package auth

import (
	"fmt"
	"testing"
	"time"
)

func Test_randomString(t *testing.T) {
	type args struct {
		len int
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
		{
			name: "test 40",
			args: args{len: 40},
		},
		{
			name: "test 5",
			args: args{len: 5},
		},
		{
			name: "test 5b",
			args: args{len: 5},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := randomString(tt.args.len)
			fmt.Println("Time: ", time.Now().UnixNano())
			fmt.Println("result: ", got)
		})
	}
}
