package whitelist

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRetryWithTimeout(t *testing.T) {

	i := 0
	assert.Nil(t, RetryWithTimeout(time.Millisecond, 1*time.Microsecond, func() bool {

		if i == 1 {
			return true
		}
		i++

		return false
	}))
	assert.Equal(t, 1, i)
}

func TestRetryWithTimeout_Timeout(t *testing.T) {

	i := 0
	err := RetryWithTimeout(100*time.Microsecond, 10*time.Microsecond, func() bool {

		i++
		return false
	})
	assert.Error(t, err)

	assert.Equal(t, "timeout", err.Error())
	assert.True(t, i > 0)
}
