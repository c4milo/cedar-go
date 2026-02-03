package eval

import (
	"context"
	"testing"
	"time"

	"github.com/cedar-policy/cedar-go/internal/testutil"
	"github.com/cedar-policy/cedar-go/types"
)

func TestLimits(t *testing.T) {
	t.Parallel()

	t.Run("DefaultLimits", func(t *testing.T) {
		t.Parallel()
		limits := DefaultLimits()
		testutil.Equals(t, limits.MaxEntityGraphDepth, 100)
		testutil.Equals(t, limits.MaxPolicyConditions, 1000)
		testutil.Equals(t, limits.EvaluationTimeout, time.Duration(0))
	})

	t.Run("NoLimits", func(t *testing.T) {
		t.Parallel()
		limits := NoLimits()
		testutil.Equals(t, limits.MaxEntityGraphDepth, 0)
		testutil.Equals(t, limits.MaxPolicyConditions, 0)
		testutil.Equals(t, limits.EvaluationTimeout, time.Duration(0))
	})
}

func TestLimitedEnv(t *testing.T) {
	t.Parallel()

	t.Run("NewLimitedEnvWithNilContext", func(t *testing.T) {
		t.Parallel()
		env := Env{}
		le := NewLimitedEnv(env, DefaultLimits(), nil)
		testutil.Equals(t, le.Ctx != nil, true)
	})

	t.Run("CheckTimeout_NoTimeout", func(t *testing.T) {
		t.Parallel()
		env := Env{}
		le := NewLimitedEnv(env, DefaultLimits(), context.Background())
		err := le.CheckTimeout()
		testutil.OK(t, err)
	})

	t.Run("CheckTimeout_Cancelled", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately
		env := Env{}
		le := NewLimitedEnv(env, DefaultLimits(), ctx)
		err := le.CheckTimeout()
		testutil.Equals(t, err != nil, true)
	})

	t.Run("CheckTimeout_DeadlineExceeded", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
		defer cancel()
		time.Sleep(time.Millisecond) // Ensure timeout
		env := Env{}
		le := NewLimitedEnv(env, DefaultLimits(), ctx)
		err := le.CheckTimeout()
		testutil.Equals(t, err, ErrEvaluationTimeout)
	})

	t.Run("IncrementConditions_NoLimit", func(t *testing.T) {
		t.Parallel()
		env := Env{}
		le := NewLimitedEnv(env, NoLimits(), nil)
		for i := 0; i < 10000; i++ {
			err := le.IncrementConditions()
			testutil.OK(t, err)
		}
	})

	t.Run("IncrementConditions_WithLimit", func(t *testing.T) {
		t.Parallel()
		limits := Limits{MaxPolicyConditions: 5}
		env := Env{}
		le := NewLimitedEnv(env, limits, nil)

		// Should succeed for the first 5
		for i := 0; i < 5; i++ {
			err := le.IncrementConditions()
			testutil.OK(t, err)
		}

		// Should fail on the 6th
		err := le.IncrementConditions()
		testutil.Equals(t, err != nil, true)
	})

	t.Run("ResetConditions", func(t *testing.T) {
		t.Parallel()
		limits := Limits{MaxPolicyConditions: 2}
		env := Env{}
		le := NewLimitedEnv(env, limits, nil)

		_ = le.IncrementConditions()
		_ = le.IncrementConditions()
		err := le.IncrementConditions()
		testutil.Equals(t, err != nil, true)

		le.ResetConditions()
		err = le.IncrementConditions()
		testutil.OK(t, err)
	})
}

func TestEntityGraphDepthLimit(t *testing.T) {
	t.Parallel()

	// Build a deep entity hierarchy: user -> group0 -> group1 -> ... -> groupN
	buildDeepHierarchy := func(depth int) types.EntityMap {
		entities := types.EntityMap{}
		prevUID := types.NewEntityUID("Group", "root")
		entities = entities.Upsert(types.Entity{UID: prevUID})

		for i := depth - 1; i >= 0; i-- {
			uid := types.NewEntityUID("Group", types.String("group"+string(rune('0'+i))))
			entities = entities.Upsert(types.Entity{
				UID:     uid,
				Parents: types.NewEntityUIDSet(prevUID),
			})
			prevUID = uid
		}

		userUID := types.NewEntityUID("User", "alice")
		entities = entities.Upsert(types.Entity{
			UID:     userUID,
			Parents: types.NewEntityUIDSet(prevUID),
		})

		return entities
	}

	t.Run("entityInOne_NoLimit", func(t *testing.T) {
		t.Parallel()
		entities := buildDeepHierarchy(50)
		env := Env{Entities: entities, Limits: nil}
		result, err := entityInOne(env,
			types.NewEntityUID("User", "alice"),
			types.NewEntityUID("Group", "root"),
		)
		testutil.OK(t, err)
		testutil.Equals(t, result, true)
	})

	t.Run("entityInOne_WithinLimit", func(t *testing.T) {
		t.Parallel()
		entities := buildDeepHierarchy(10)
		limits := &Limits{MaxEntityGraphDepth: 50}
		env := Env{Entities: entities, Limits: limits}
		result, err := entityInOne(env,
			types.NewEntityUID("User", "alice"),
			types.NewEntityUID("Group", "root"),
		)
		testutil.OK(t, err)
		testutil.Equals(t, result, true)
	})

	t.Run("entityInOne_ExceedsLimit", func(t *testing.T) {
		t.Parallel()
		entities := buildDeepHierarchy(50)
		limits := &Limits{MaxEntityGraphDepth: 5}
		env := Env{Entities: entities, Limits: limits}
		_, err := entityInOne(env,
			types.NewEntityUID("User", "alice"),
			types.NewEntityUID("Group", "root"),
		)
		testutil.Equals(t, err, ErrEntityDepthExceeded)
	})

	t.Run("entityInSet_NoLimit", func(t *testing.T) {
		t.Parallel()
		entities := buildDeepHierarchy(50)
		env := Env{Entities: entities, Limits: nil}
		result, err := entityInSet(env,
			types.NewEntityUID("User", "alice"),
			types.NewEntityUIDSet(types.NewEntityUID("Group", "root")),
		)
		testutil.OK(t, err)
		testutil.Equals(t, result, true)
	})

	t.Run("entityInSet_ExceedsLimit", func(t *testing.T) {
		t.Parallel()
		entities := buildDeepHierarchy(50)
		limits := &Limits{MaxEntityGraphDepth: 5}
		env := Env{Entities: entities, Limits: limits}
		_, err := entityInSet(env,
			types.NewEntityUID("User", "alice"),
			types.NewEntityUIDSet(types.NewEntityUID("Group", "root")),
		)
		testutil.Equals(t, err, ErrEntityDepthExceeded)
	})
}
