package internal

import (
	"bytes"
)

type nopCloser struct {
	data bytes.Buffer
}

func (c *nopCloser) Close() error {
	return nil
}

func (c *nopCloser) Write(p []byte) (n int, err error) {
	return c.data.Write(p)
}

func (c *nopCloser) String() string {
	return c.data.String()
}

func NopCloser() *nopCloser {
	return &nopCloser{}
}
