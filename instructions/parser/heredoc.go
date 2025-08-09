package parser

import (
	"strconv"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/shell"
	"github.com/pkg/errors"
)

type Heredoc struct {
	Name           string
	FileDescriptor uint
	Expand         bool
	Chomp          bool
	Content        string
}

// heredocFromMatch extracts a heredoc from a possible heredoc regex match.
func heredocFromMatch(match []string) (*Heredoc, error) {
	if len(match) == 0 {
		return nil, nil
	}

	fd, _ := strconv.ParseUint(match[1], 10, 0)
	chomp := match[2] == "-"
	rest := match[3]

	if len(rest) == 0 {
		return nil, nil
	}

	shlex := shell.NewLex('\\')
	shlex.SkipUnsetEnv = true

	// Attempt to parse both the heredoc both with *and* without quotes.
	// If there are quotes in one but not the other, then we know that some
	// part of the heredoc word is quoted, so we shouldn't expand the content.
	shlex.RawQuotes = false
	words, err := shlex.ProcessWords(rest, emptyEnvs{})
	if err != nil {
		return nil, err
	}
	// quick sanity check that rest is a single word
	if len(words) != 1 {
		return nil, nil
	}

	shlex.RawQuotes = true
	wordsRaw, err := shlex.ProcessWords(rest, emptyEnvs{})
	if err != nil {
		return nil, err
	}
	if len(wordsRaw) != len(words) {
		return nil, errors.Errorf("internal lexing of heredoc produced inconsistent results: %s", rest)
	}

	word := words[0]
	wordQuoteCount := strings.Count(word, `'`) + strings.Count(word, `"`)
	wordRaw := wordsRaw[0]
	wordRawQuoteCount := strings.Count(wordRaw, `'`) + strings.Count(wordRaw, `"`)

	expand := wordQuoteCount == wordRawQuoteCount

	return &Heredoc{
		Name:           word,
		Expand:         expand,
		Chomp:          chomp,
		FileDescriptor: uint(fd),
	}, nil
}

func heredocsFromLine(line string) ([]Heredoc, error) {
	shlex := shell.NewLex('\\')
	shlex.RawQuotes = true
	shlex.RawEscapes = true
	shlex.SkipUnsetEnv = true
	words, _ := shlex.ProcessWords(line, emptyEnvs{})

	var docs []Heredoc
	for _, word := range words {
		heredoc, err := ParseHeredoc(word)
		if err != nil {
			return nil, err
		}
		if heredoc != nil {
			docs = append(docs, *heredoc)
		}
	}
	return docs, nil
}

// ChompHeredocContent chomps leading tabs from the heredoc.
func ChompHeredocContent(src string) string {
	return reLeadingTabs.ReplaceAllString(src, "")
}

type emptyEnvs struct{}

func (emptyEnvs) Get(string) (string, bool) {
	return "", false
}

func (emptyEnvs) Keys() []string {
	return nil
}
