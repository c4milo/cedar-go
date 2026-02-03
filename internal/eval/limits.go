package eval

import (
	"context"
	"errors"
	"time"
)

// Limit-related errors
var (
	ErrEntityDepthExceeded = errors.New("entity graph depth limit exceeded")
	ErrEvaluationTimeout   = errors.New("evaluation timeout")
)

// Limits configures resource limits for policy evaluation to protect against
// DoS attacks. Zero values indicate no limit.
type Limits struct {
	// MaxEntityGraphDepth limits how deep entity hierarchy traversal can go
	// when evaluating "in" operators. Default 0 means unlimited.
	MaxEntityGraphDepth int

	// MaxPolicyConditions limits the number of conditions that can be evaluated
	// in a single policy. Default 0 means unlimited.
	MaxPolicyConditions int

	// EvaluationTimeout sets a maximum duration for evaluating all policies.
	// Default 0 means no timeout.
	EvaluationTimeout time.Duration
}

// DefaultLimits returns conservative default limits suitable for production use.
// These defaults protect against common DoS vectors while allowing reasonable
// policy complexity.
func DefaultLimits() Limits {
	return Limits{
		MaxEntityGraphDepth: 100,  // Prevent infinite loops in cyclic graphs
		MaxPolicyConditions: 1000, // Reasonable policy complexity
		EvaluationTimeout:   0,    // No timeout by default (callers should set context)
	}
}

// NoLimits returns a Limits configuration with all limits disabled.
// Use with caution - only appropriate for trusted policy sources.
func NoLimits() Limits {
	return Limits{}
}

// LimitedEnv wraps an Env with resource limits and optional context for timeout.
type LimitedEnv struct {
	Env
	Limits Limits
	Ctx    context.Context

	// Internal counters for tracking evaluation progress
	conditionsEvaluated int
}

// NewLimitedEnv creates a LimitedEnv with the given limits.
// If ctx is nil, context.Background() is used (no timeout).
func NewLimitedEnv(env Env, limits Limits, ctx context.Context) *LimitedEnv {
	if ctx == nil {
		ctx = context.Background()
	}
	return &LimitedEnv{
		Env:    env,
		Limits: limits,
		Ctx:    ctx,
	}
}

// CheckTimeout checks if the evaluation context has been cancelled or timed out.
func (e *LimitedEnv) CheckTimeout() error {
	select {
	case <-e.Ctx.Done():
		if e.Ctx.Err() == context.DeadlineExceeded {
			return ErrEvaluationTimeout
		}
		return e.Ctx.Err()
	default:
		return nil
	}
}

// IncrementConditions increments the condition counter and returns an error
// if the limit is exceeded.
func (e *LimitedEnv) IncrementConditions() error {
	if e.Limits.MaxPolicyConditions <= 0 {
		return nil
	}
	e.conditionsEvaluated++
	if e.conditionsEvaluated > e.Limits.MaxPolicyConditions {
		return errors.New("policy condition limit exceeded")
	}
	return nil
}

// ResetConditions resets the condition counter for a new policy evaluation.
func (e *LimitedEnv) ResetConditions() {
	e.conditionsEvaluated = 0
}
