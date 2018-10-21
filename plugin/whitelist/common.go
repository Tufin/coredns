package whitelist

import (
	"errors"
	"time"
)

func RetryWithTimeout(timeout time.Duration, sleep time.Duration, f func() bool) error {

	deadline := time.After(timeout)
	for {
		select {
		case <-deadline:
			return errors.New("timeout")
		default:
			if ok := f(); ok {
				return nil
			}
			time.Sleep(sleep)
		}
	}

	return nil
}

func GetEnv(variable string) string {

	ret := GetEnv(variable)
	log.Infof("'%s': '%s'", variable, ret)

	return ret
}
