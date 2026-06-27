package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
)

// Reloader refreshes runtime state that can be updated without a full restart.
type Reloader interface {
	Reload(ctx context.Context) error
}

type service struct {
	run       func(context.Context) error
	errPrefix string
}

// Runtime owns the process services for one loaded configuration.
type Runtime struct {
	cause    error
	reloader Reloader
	cancel   context.CancelCauseFunc
	done     <-chan struct{}
	logger   *slog.Logger
	services []service
	stopped  bool
	wg       sync.WaitGroup
	causeMu  sync.Mutex
}

func newRuntime(logger *slog.Logger, reloader Reloader, services []service) *Runtime {
	return &Runtime{
		logger:   logger,
		reloader: reloader,
		services: services,
	}
}

// Start starts all services and records the first service error as the runtime
// cancellation cause.
func (r *Runtime) Start(ctx context.Context) {
	ctx, cancel := context.WithCancelCause(ctx)
	r.cancel = cancel
	r.done = ctx.Done()

	for _, svc := range r.services {
		r.wg.Go(func() {
			if err := svc.run(ctx); err != nil {
				r.Stop(fmt.Errorf("%s: %w", svc.errPrefix, err))

				return
			}

			r.Stop(nil)
		})
	}
}

// Done is closed when the runtime is stopping.
func (r *Runtime) Done() <-chan struct{} {
	return r.done
}

// Err returns the cause that stopped the runtime.
func (r *Runtime) Err() error {
	r.causeMu.Lock()
	defer r.causeMu.Unlock()

	return r.cause
}

// Stop requests shutdown with the supplied cause.
func (r *Runtime) Stop(cause error) {
	r.causeMu.Lock()
	if !r.stopped {
		r.stopped = true
		r.cause = cause
	}
	r.causeMu.Unlock()

	if r.cancel != nil {
		r.cancel(cause)
	}
}

// Wait blocks until all runtime services have exited.
func (r *Runtime) Wait() {
	r.wg.Wait()
}

// Reload refreshes reloadable runtime state.
func (r *Runtime) Reload(ctx context.Context) error {
	if r.reloader == nil {
		return nil
	}

	if err := r.reloader.Reload(ctx); err != nil {
		return fmt.Errorf("error reloading http server: %w", err)
	}

	return nil
}

// LogSignal records a signal received by the command package.
func (r *Runtime) LogSignal(ctx context.Context, sig string) {
	r.logger.LogAttrs(ctx, slog.LevelInfo, "receiving signal: "+sig)
}
