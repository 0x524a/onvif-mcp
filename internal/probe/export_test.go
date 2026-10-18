package probe

import (
	"context"

	"github.com/0x524A/rtspeek/pkg/rtspeek"
)

func rtspeekDebugContext(ctx context.Context) context.Context { return rtspeek.WithDebug(ctx) }
