package core

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/rs/zerolog"
)

func TestSelfTestExercisesDetectionAndVerifiedRedaction(t *testing.T) {
	checks := SelfTest()
	if len(checks) != 2 {
		t.Fatalf("SelfTest returned %d checks, want 2", len(checks))
	}
	for _, check := range checks {
		if !check.OK {
			t.Errorf("%s failed: %s", check.ID, check.Message)
		}
	}
}

func TestBetterleaksFatalInitializationIsRecoverable(t *testing.T) {
	previousLogger := logging.Logger
	logging.Logger = zerolog.New(io.Discard)
	t.Cleanup(func() { logging.Logger = previousLogger })

	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatal("newDetectorContext(nil config) did not panic")
		}
		if !strings.Contains(fmt.Sprint(recovered), "betterleaks reported a fatal initialization error") {
			t.Fatalf("panic = %q, want Betterleaks fatal sentinel", recovered)
		}
	}()
	newDetectorContext(context.Background(), nil)
}
