package main

import (
	"context"
	"database/sql"

	"github.com/doublemo/linna-common/api"
	"github.com/doublemo/linna-common/runtime"
)

func processEvent(ctx context.Context, logger runtime.Logger, evt *api.Event) {
	switch evt.GetName() {
	case "account_updated":
		logger.Debug("process evt: %+v", evt)
		// Send event to an analytics service.
	default:
		logger.Error("unrecognised evt: %+v", evt)
	}
}

func eventSessionEnd(ctx context.Context, logger runtime.Logger, evt *api.Event) {
	logger.Debug("process event session end: %+v", evt)
}

func eventSessionStart(ctx context.Context, logger runtime.Logger, evt *api.Event) {
	logger.Debug("process event session start: %+v", evt)
}

//noinspection GoUnusedExportedFunction
func InitModule(ctx context.Context, logger runtime.Logger, db *sql.DB, nk runtime.LinnaModule, initializer runtime.Initializer) error {

	if err := initializer.RegisterEvent(processEvent); err != nil {
		return err
	}
	if err := initializer.RegisterEventSessionEnd(eventSessionEnd); err != nil {
		return err
	}
	if err := initializer.RegisterEventSessionStart(eventSessionStart); err != nil {
		return err
	}
	logger.Info("Server loaded.")
	return nil
}
