package import_server

import (
	"reflect"
	"sort"
	"testing"
)

func Test_globToRsyncFilterPaths(t *testing.T) {
	type args struct {
		glob             string
		finalSegmentOnly bool
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "empty glob",
			args: args{glob: "", finalSegmentOnly: false},
			want: nil,
		},
		{
			name: "simple glob (all paths)",
			args: args{glob: "a/b/c", finalSegmentOnly: false},
			want: []string{"a/", "a/b/", "a/b/c"},
		},
		{
			name: "simple glob (only final)",
			args: args{glob: "a/b/c", finalSegmentOnly: true},
			want: []string{"a/b/c"},
		},
		{
			name: "** recursion (all paths)",
			args: args{glob: "a/b/**/c", finalSegmentOnly: false},
			want: []string{"a/", "a/b/", "a/b/**/", "a/b/c", "a/b/**/c"},
		},
		{
			name: "** recursion (only final)",
			args: args{glob: "a/b/**/c", finalSegmentOnly: true},
			want: []string{"a/b/c", "a/b/**/c"},
		},
		{
			name: "mixed c* (all paths)",
			args: args{glob: "a/b/**/c*", finalSegmentOnly: false},
			want: []string{"a/", "a/b/", "a/b/**/", "a/b/c*", "a/b/**/c*"},
		},
		{
			name: "mixed c* (only final)",
			args: args{glob: "a/b/**/c*", finalSegmentOnly: true},
			want: []string{"a/b/c*", "a/b/**/c*"},
		},
		{
			name: "mixed c? (all paths)",
			args: args{glob: "a/b/**/c?", finalSegmentOnly: false},
			want: []string{"a/", "a/b/", "a/b/**/", "a/b/c?", "a/b/**/c?"},
		},
		{
			name: "mixed c? (only final)",
			args: args{glob: "a/b/**/c?", finalSegmentOnly: true},
			want: []string{"a/b/c?", "a/b/**/c?"},
		},
		{
			name: "char class (all paths)",
			args: args{glob: "a/b/**/c[abc]", finalSegmentOnly: false},
			want: []string{"a/", "a/b/", "a/b/**/", "a/b/c[abc]", "a/b/**/c[abc]"},
		},
		{
			name: "char class (only final)",
			args: args{glob: "a/b/**/c[abc]", finalSegmentOnly: true},
			want: []string{"a/b/c[abc]", "a/b/**/c[abc]"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := globToRsyncFilterPaths(tt.args.glob, tt.args.finalSegmentOnly)
			sort.Strings(got)
			sort.Strings(tt.want)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("globDescentPath(%q, %v) = %v, want %v",
					tt.args.glob, tt.args.finalSegmentOnly, got, tt.want)
			}
		})
	}
}

func TestPrepareRsyncFilters(t *testing.T) {
	tests := []struct {
		name         string
		add          string
		includePaths []string
		excludePaths []string
		want         string
	}{
		{
			name: "no paths leave the copy command unfiltered",
			add:  "/opt/app",
		},
		{
			name:         "excludes alone prune the named paths",
			add:          "/opt/app",
			excludePaths: []string{"keep/secret", "logs/*"},
			want:         " --filter='-/ opt/app/keep/secret' --filter='-/ opt/app/logs/*'",
		},
		{
			name:         "excludes are read before the includes that carry a path",
			add:          "/opt/app",
			includePaths: []string{"keep"},
			excludePaths: []string{"keep/secret"},
			want:         " --filter='-/ opt/app/keep/secret' --filter='+/ /opt/app/keep' --filter='+/ /opt/app/keep/**' --filter='+/ opt/' --filter='+/ opt/app/' --filter='+/ opt/app/keep' --filter='-/ /opt/app/**'",
		},
		{
			name:         "a double star include keeps every prefix traversable",
			add:          "/opt/app",
			includePaths: []string{"a/**/b"},
			want:         " --filter='+/ /opt/app/a/**/b' --filter='+/ /opt/app/a/**/b/**' --filter='+/ opt/' --filter='+/ opt/app/' --filter='+/ opt/app/a/' --filter='+/ opt/app/a/**/' --filter='+/ opt/app/a/**/b' --filter='+/ opt/app/a/b' --filter='-/ /opt/app/**'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PrepareRsyncFilters(tt.add, tt.includePaths, tt.excludePaths); got != tt.want {
				t.Errorf("PrepareRsyncFilters(%q, %v, %v) = %q, want %q", tt.add, tt.includePaths, tt.excludePaths, got, tt.want)
			}
		})
	}
}
