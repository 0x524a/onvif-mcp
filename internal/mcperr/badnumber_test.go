package mcperr

import (
	"fmt"
	"strconv"
	"testing"
)

func TestOutOfRangeNumberIsDeviceFault(t *testing.T) {
	_, perr := strconv.ParseFloat("1e999", 64)
	for _, err := range []error{perr, fmt.Errorf("GetStatus: %w", perr)} {
		te := FromError(err, "cam", "GetStatus")
		if te.Code != CodeDeviceFault || te.Hint == "" || te.Retryable {
			t.Errorf("got code=%s retryable=%v hint=%q", te.Code, te.Retryable, te.Hint)
		}
	}
}
