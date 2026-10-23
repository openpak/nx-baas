package main

import "testing"

// nx-baas no longer serves the eShop, Penne or parental controls itself, so main refuses to
// start without the URL of each service that does. Tests build servers directly and never
// reach that check.
func TestMissingForwardNamesTheVariable(t *testing.T) {
	for _, f := range requiredForwards {
		t.Setenv(f.env, "http://"+f.service+":20070")
	}
	if env, _ := missingForward(); env != "" {
		t.Fatalf("all set, still missing %s", env)
	}
	for _, f := range requiredForwards {
		t.Run(f.env, func(t *testing.T) {
			t.Setenv(f.env, "")
			env, service := missingForward()
			if env != f.env || service != f.service {
				t.Fatalf("unset %s: missingForward = %q, %q", f.env, env, service)
			}
		})
	}
	t.Setenv("NX_BCAT_URL", "")
	if env, _ := missingForward(); env != "" {
		t.Fatalf("NX_BCAT_URL is optional, but %s reported missing", env)
	}
}
