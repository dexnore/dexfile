package internal

import "io"

type WriteCloseStringer interface {
	io.WriteCloser
	String() string
}
