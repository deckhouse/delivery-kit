package utils

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	werfExec "github.com/werf/werf/v2/pkg/werf/exec"
)

func RunCommand(ctx context.Context, dir, command string, args ...string) ([]byte, error) {
	return RunCommandWithOptions(ctx, dir, command, args, RunCommandOptions{ShouldSucceed: false})
}

func RunSucceedCommand(ctx context.Context, dir, command string, args ...string) {
	_, _ = RunCommandWithOptions(ctx, dir, command, args, RunCommandOptions{ShouldSucceed: true})
}

func SucceedCommandOutputString(ctx context.Context, dir, command string, args ...string) string {
	res, _ := RunCommandWithOptions(ctx, dir, command, args, RunCommandOptions{ShouldSucceed: true})
	return string(res)
}

type RunCommandOptions struct {
	ExtraEnv      []string
	ToStdin       string
	ShouldSucceed bool
	NoStderr      bool

	// CancelOnOutput cancels the command once this substring appears in its output.
	// The wait is bounded by CancelOnOutputTimeout, counted from the moment
	// CancelOnOutputAfter appears (or from start when it is empty); the wait for
	// CancelOnOutputAfter itself is bounded only by ctx.
	CancelOnOutput        string
	CancelOnOutputAfter   string
	CancelOnOutputTimeout time.Duration
}

func RunCommandWithOptions(ctx context.Context, dir, command string, args []string, options RunCommandOptions) ([]byte, error) {
	cmd := exec.CommandContext(ctx, command, args...)
	cmd = werfExec.PrepareGracefulCancellation(cmd)

	if dir != "" {
		cmd.Dir = dir
	}

	cmd.Env = append(os.Environ(), options.ExtraEnv...)

	if options.ToStdin != "" {
		cmd.Stdin = bytes.NewReader([]byte(options.ToStdin))
	}

	res := newCommandOutput(options.CancelOnOutput, options.CancelOnOutputAfter)
	cmd.Stdout = res
	if !options.NoStderr {
		cmd.Stderr = res
	}

	Expect(cmd.Start()).To(Succeed())

	if options.CancelOnOutput != "" {
		if options.CancelOnOutputAfter != "" {
			select {
			case <-res.cancelWindowOpened:
			case <-ctx.Done():
			}
		}
		if ctx.Err() == nil {
			res.waitForOutput(options.CancelOnOutputTimeout)
			Expect(cmd.Cancel()).To(Succeed())
		}
	}

	err := cmd.Wait()
	output := res.Bytes()

	if options.ShouldSucceed {
		errorDesc := fmt.Sprintf("%[2]s %[3]s (dir: %[1]s)", dir, command, strings.Join(args, " "))
		Expect(err).ShouldNot(HaveOccurred(), errorDesc)
	}

	return output, err
}

type commandOutput struct {
	mux                sync.Mutex
	buffer             bytes.Buffer
	cancelOnOutput     string
	cancelAfter        string
	outputDetected     chan struct{}
	outputOnce         sync.Once
	cancelWindowOpened chan struct{}
	cancelWindowOnce   sync.Once
}

var _ io.Writer = (*commandOutput)(nil)

func newCommandOutput(cancelOnOutput, cancelAfter string) *commandOutput {
	return &commandOutput{
		cancelOnOutput:     cancelOnOutput,
		cancelAfter:        cancelAfter,
		outputDetected:     make(chan struct{}),
		cancelWindowOpened: make(chan struct{}),
	}
}

func (output *commandOutput) Write(p []byte) (int, error) {
	output.mux.Lock()
	defer output.mux.Unlock()

	n, err := output.buffer.Write(p)
	_, _ = GinkgoWriter.Write(p[:n])
	if output.cancelAfter != "" && bytes.Contains(output.buffer.Bytes(), []byte(output.cancelAfter)) {
		output.cancelWindowOnce.Do(func() {
			close(output.cancelWindowOpened)
		})
	}
	if output.cancelOnOutput != "" && bytes.Contains(output.buffer.Bytes(), []byte(output.cancelOnOutput)) {
		output.outputOnce.Do(func() {
			close(output.outputDetected)
		})
	}

	return n, err
}

func (output *commandOutput) Bytes() []byte {
	output.mux.Lock()
	defer output.mux.Unlock()

	return bytes.Clone(output.buffer.Bytes())
}

func (output *commandOutput) waitForOutput(timeout time.Duration) {
	if timeout == 0 {
		timeout = time.Minute
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-output.outputDetected:
	case <-timer.C:
	}
}

func ShelloutPack(command string) string {
	return fmt.Sprintf("eval $(echo %s | base64 -d)", base64.StdEncoding.EncodeToString([]byte(command)))
}
