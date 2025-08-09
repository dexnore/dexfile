package parser

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"unicode"

	"github.com/pkg/errors"
)

// Parse consumes lines from a provided Reader, parses each line into an AST
// and returns the results of doing so.
func Parse(rwc io.Reader) (*Result, error) {
	d := newDefaultDirectives()
	currentLine := 0
	root := &Node{StartLine: -1}
	scanner := bufio.NewScanner(rwc)
	scanner.Split(scanLines)
	warnings := []Warning{}
	var comments []string
	buf := &bytes.Buffer{}

	var err error
	for scanner.Scan() {
		bytesRead := scanner.Bytes()
		if currentLine == 0 {
			// First line, strip the byte-order-marker if present
			bytesRead = discardBOM(bytesRead)
		}
		if isComment(bytesRead) {
			comment := strings.TrimSpace(string(bytesRead[1:]))
			if comment == "" {
				comments = nil
			} else {
				comments = append(comments, comment)
			}
		}
		var directiveOk bool
		bytesRead, directiveOk, err = processLine(d, bytesRead, true)
		// If the line is a directive, strip it from the comments
		// so it doesn't get added to the AST.
		if directiveOk {
			comments = comments[:len(comments)-1]
		}
		if err != nil {
			return nil, withLocation(err, currentLine, 0)
		}
		currentLine++

		startLine := currentLine
		bytesRead, isEndOfLine := trimContinuationCharacter(bytesRead, d)
		if isEndOfLine && len(bytesRead) == 0 {
			continue
		}
		buf.Reset()
		buf.Write(bytesRead)

		var hasEmptyContinuationLine bool
		for !isEndOfLine && scanner.Scan() {
			bytesRead, _, err := processLine(d, scanner.Bytes(), false)
			if err != nil {
				return nil, withLocation(err, currentLine, 0)
			}
			currentLine++

			if isComment(scanner.Bytes()) {
				// original line was a comment (processLine strips comments)
				continue
			}
			if isEmptyContinuationLine(bytesRead) {
				hasEmptyContinuationLine = true
				continue
			}

			bytesRead, isEndOfLine = trimContinuationCharacter(bytesRead, d)
			buf.Write(bytesRead)
		}

		line := buf.String()

		if hasEmptyContinuationLine {
			warnings = append(warnings, Warning{
				Short:    "Empty continuation line found in: " + line,
				Detail:   [][]byte{[]byte("Empty continuation lines will become errors in a future release")},
				URL:      "https://docs.docker.com/go/dockerfile/rule/no-empty-continuation/",
				Location: &Range{Start: Position{Line: currentLine}, End: Position{Line: currentLine}},
			})
		}

		child, err := newNodeFromLine(line, d, comments)
		if err != nil {
			return nil, withLocation(err, startLine, currentLine)
		}

		if child.canContainHeredoc() && strings.Contains(line, "<<") {
			heredocs, err := heredocsFromLine(line)
			if err != nil {
				return nil, withLocation(err, startLine, currentLine)
			}

			for _, heredoc := range heredocs {
				terminator := []byte(heredoc.Name)
				terminated := false
				for scanner.Scan() {
					bytesRead := scanner.Bytes()
					currentLine++

					possibleTerminator := trimNewline(bytesRead)
					if heredoc.Chomp {
						possibleTerminator = trimLeadingTabs(possibleTerminator)
					}
					if bytes.Equal(possibleTerminator, terminator) {
						terminated = true
						break
					}
					heredoc.Content += string(bytesRead)
				}
				if !terminated {
					return nil, withLocation(errors.New("unterminated heredoc"), startLine, currentLine)
				}

				child.Heredocs = append(child.Heredocs, heredoc)
			}
		}

		root.AddChild(child, startLine, currentLine)
		comments = nil
	}

	if root.StartLine < 0 {
		return nil, withLocation(errors.New("file with no instructions"), currentLine, 0)
	}

	return &Result{
		AST:         root,
		Warnings:    warnings,
		EscapeToken: d.escapeToken,
	}, withLocation(handleScannerError(scanner.Err()), currentLine, 0)
}

// ParseHeredoc parses a heredoc word from a target string, returning the
// components from the doc.
func ParseHeredoc(src string) (*Heredoc, error) {
	return heredocFromMatch(reHeredoc.FindStringSubmatch(src))
}

// MustParseHeredoc is a variant of ParseHeredoc that discards the error, if
// there was one present.
func MustParseHeredoc(src string) *Heredoc {
	heredoc, _ := ParseHeredoc(src)
	return heredoc
}

func trimComments(src []byte) []byte {
	if !isComment(src) {
		return src
	}
	return nil
}

func trimLeadingWhitespace(src []byte) []byte {
	return bytes.TrimLeftFunc(src, unicode.IsSpace)
}
func trimLeadingTabs(src []byte) []byte {
	return bytes.TrimLeft(src, "\t")
}
func trimNewline(src []byte) []byte {
	return bytes.TrimRight(src, "\r\n")
}

func isComment(line []byte) bool {
	line = trimLeadingWhitespace(line)
	return len(line) > 0 && line[0] == '#'
}

func isEmptyContinuationLine(line []byte) bool {
	return len(trimLeadingWhitespace(trimNewline(line))) == 0
}

func trimContinuationCharacter(line []byte, d *directives) ([]byte, bool) {
	if d.lineContinuationRegex.Match(line) {
		line = d.lineContinuationRegex.ReplaceAll(line, []byte("$1"))
		return line, false
	}
	return line, true
}

// TODO: remove stripLeftWhitespace after deprecation period. It seems silly
// to preserve whitespace on continuation lines. Why is that done?
func processLine(d *directives, token []byte, stripLeftWhitespace bool) ([]byte, bool, error) {
	token = trimNewline(token)
	if stripLeftWhitespace {
		token = trimLeadingWhitespace(token)
	}
	directiveOk, err := d.possibleParserDirective(token)
	return trimComments(token), directiveOk, err
}

// Variation of bufio.ScanLines that preserves the line endings
func scanLines(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		return i + 1, data[0 : i+1], nil
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func handleScannerError(err error) error {
	switch {
	case errors.Is(err, bufio.ErrTooLong):
		return errors.Errorf("dexfile line greater than max allowed size of %d", bufio.MaxScanTokenSize-1)
	default:
		return err
	}
}
