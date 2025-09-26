package mapx_test

import (
	"fmt"
	"testing"

	"github.com/axent-pl/auth/mapx"
)

func TestGet(t *testing.T) {
	data := map[string]any{
		"foo": "bar",
		"foos": []string{
			"bar1",
			"bar2",
		},
		"foofoo": map[string]any{
			"foo": "barbar",
		},
	}
	tests := []struct {
		name    string
		root    any
		path    string
		want    []any
		wantErr bool
	}{
		// {
		// 	name:    "simple",
		// 	root:    data,
		// 	path:    ".foo",
		// 	want:    []any{"bar"},
		// 	wantErr: false,
		// },
		// {
		// 	name:    "list",
		// 	root:    data,
		// 	path:    ".foos",
		// 	want:    []any{[]any{"bar1", "bar2"}},
		// 	wantErr: false,
		// },
		// {
		// 	name:    "list by index",
		// 	root:    data,
		// 	path:    ".foos[0]",
		// 	want:    []any{"bar1"},
		// 	wantErr: false,
		// },
		// {
		// 	name:    "list by negative index",
		// 	root:    data,
		// 	path:    ".foos[-1]",
		// 	want:    []any{"bar2"},
		// 	wantErr: false,
		// },
		{
			name:    "recursive map",
			root:    data,
			path:    "..foo",
			want:    []any{"bar", "barbar"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := mapx.Get(tt.root, tt.path)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Get() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Get() succeeded unexpectedly")
			}
			if fmt.Sprintf("%+v", tt.want) != fmt.Sprintf("%+v", got) {
				t.Errorf("Get() = %v, want %v", got, tt.want)
			}
		})
	}
}
