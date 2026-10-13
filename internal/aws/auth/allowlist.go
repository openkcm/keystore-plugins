package auth

import (
	"fmt"
	"regexp"
	"strings"
)

// allowList matches role ARNs against patterns in which "*" matches any
// characters, including "/" and ":". An empty list allows every ARN.
type allowList []*regexp.Regexp

func newAllowList(patterns []string) allowList {
	list := make(allowList, 0, len(patterns))
	for _, p := range patterns {
		expr := "^" + strings.ReplaceAll(regexp.QuoteMeta(strings.TrimSpace(p)), `\*`, ".*") + "$"
		list = append(list, regexp.MustCompile(expr))
	}

	return list
}

func (l allowList) check(roleArn string) error {
	if len(l) == 0 {
		return nil
	}

	for _, re := range l {
		if re.MatchString(roleArn) {
			return nil
		}
	}

	return fmt.Errorf("%w: %w: %s", ErrResolveCredentials, ErrRoleNotAllowed, roleArn)
}
