package internal

import (
	"fmt"
	"time"
)

func FormatDuration(dur time.Duration) string {
	switch {
	case dur > time.Hour:
		return fmt.Sprintf("%d hours", dur/time.Hour)
	case dur > time.Minute:
		return fmt.Sprintf("%d minutes", dur/time.Minute)
	default:
		return fmt.Sprintf("%d seconds", dur/time.Second)
	}
}
