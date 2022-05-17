package main

import (
	"context"
	"database/sql"

	"github.com/doublemo/linna-common/runtime"
)

func InitModule(ctx context.Context, logger runtime.Logger, db *sql.DB, na runtime.LinnaModule, initializer runtime.Initializer) error {
	logger.Debug("Hello world.")
	return nil
}
