package common

type SubjectID string

type Principal struct {
	Subject    SubjectID
	Attributes map[string]any
}
