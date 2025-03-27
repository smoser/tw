package control

import "time"

type Command string

const (
	CommandStart Command = "start"
	CommandStop  Command = "end"
	CommandSkip  Command = "skip"
)

type Message struct {
	Command  Command   `json:"command"`
	TestName string    `json:"test_name"`
	ExitCode int       `json:"exit_code"`
	Time     time.Time `json:"time"`
	Message  string    `json:"message,omitempty"`
}

type Ack struct{}
