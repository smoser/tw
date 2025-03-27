package pipe

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// Pipe represents a named pipe on disk
type Pipe struct {
	Path   string
	closed chan struct{}
}

func New(path string) (*Pipe, error) {
	if err := unix.Mkfifo(path, 0666); err != nil {
		return nil, err
	}
	return &Pipe{
		Path: path,

		closed: make(chan struct{}),
	}, nil
}

func (p *Pipe) Open() (io.Reader, error) {
	select {
	case <-p.closed:
		return nil, fmt.Errorf("pipe %s is closed", p.Path)
	default:
	}
	return os.OpenFile(p.Path, os.O_RDONLY, 0)
}

func (p *Pipe) Close() error {
	select {
	case <-p.closed:
		return fmt.Errorf("pipe %s is already closed", p.Path)
	default:
		close(p.closed)
		return os.Remove(p.Path)
	}
}
