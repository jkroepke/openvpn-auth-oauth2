//nolint:testpackage // Tests exercise unexported lifecycle seams without full daemon wiring.
package daemon

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRuntimeReloadWrapsError(t *testing.T) {
	t.Parallel()

	expectedErr := errors.New("reload failed")
	runtime := newRuntime(
		slog.New(slog.DiscardHandler),
		reloaderFunc(func(context.Context) error {
			return expectedErr
		}),
		nil,
	)

	err := runtime.Reload(t.Context())

	require.ErrorIs(t, err, expectedErr)
	require.ErrorContains(t, err, "error reloading http server")
}

func TestRuntimeServiceErrorStopsRuntime(t *testing.T) {
	t.Parallel()

	expectedErr := errors.New("listen failed")
	runtime := newRuntime(
		slog.New(slog.DiscardHandler),
		nil,
		[]service{
			{
				errPrefix: "test service",
				run: func(context.Context) error {
					return expectedErr
				},
			},
		},
	)

	runtime.Start(t.Context())
	<-runtime.Done()
	runtime.Wait()

	require.ErrorIs(t, runtime.Err(), expectedErr)
	require.ErrorContains(t, runtime.Err(), "test service")
}

func TestRuntimeCleanStopKeepsNilCause(t *testing.T) {
	t.Parallel()

	expectedErr := errors.New("late shutdown error")
	runtime := newRuntime(
		slog.New(slog.DiscardHandler),
		nil,
		[]service{
			{
				errPrefix: "test service",
				run: func(ctx context.Context) error {
					<-ctx.Done()

					return expectedErr
				},
			},
		},
	)

	runtime.Start(t.Context())
	runtime.Stop(nil)
	<-runtime.Done()
	runtime.Wait()

	require.NoError(t, runtime.Err())
}

type reloaderFunc func(context.Context) error

func (f reloaderFunc) Reload(ctx context.Context) error {
	return f(ctx)
}
