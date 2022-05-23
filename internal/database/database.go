package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgconn"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v4/stdlib"
	"go.uber.org/zap"
)

// Configuration 配置
type Configuration struct {
	Addresses          []string `yaml:"address" json:"address" usage:"List of database servers (username:password@address:port/dbname). Default 'root@localhost:26257'."`
	ConnMaxLifetimeMs  int      `yaml:"conn_max_lifetime_ms" json:"conn_max_lifetime_ms" usage:"Time in milliseconds to reuse a database connection before the connection is killed and a new one is created. Default 3600000 (1 hour)."`
	MaxOpenConns       int      `yaml:"max_open_conns" json:"max_open_conns" usage:"Maximum number of allowed open connections to the database. Default 100."`
	MaxIdleConns       int      `yaml:"max_idle_conns" json:"max_idle_conns" usage:"Maximum number of allowed open but unused connections to the database. Default 100."`
	DnsScanIntervalSec int      `yaml:"dns_scan_interval_sec" json:"dns_scan_interval_sec" usage:"Number of seconds between scans looking for DNS resolution changes for the database hostname. Default 60."`
}

// NewConfiguration creates a new Configuration struct.
func NewConfiguration() Configuration {
	return Configuration{
		Addresses:          []string{"root@localhost:26257"},
		ConnMaxLifetimeMs:  3600000,
		MaxOpenConns:       100,
		MaxIdleConns:       100,
		DnsScanIntervalSec: 60,
	}
}

var ErrDatabaseDriverMismatch = errors.New("database driver mismatch")

func DbConnect(ctx context.Context, logger *zap.Logger, config Configuration) (*sql.DB, string) {
	rawURL := config.Addresses[0]
	if !(strings.HasPrefix(rawURL, "postgresql://") || strings.HasPrefix(rawURL, "postgres://")) {
		rawURL = fmt.Sprintf("postgres://%s", rawURL)
	}
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		logger.Fatal("Bad database connection URL", zap.Error(err))
	}
	query := parsedURL.Query()
	if len(query.Get("sslmode")) == 0 {
		query.Set("sslmode", "prefer")
		parsedURL.RawQuery = query.Encode()
	}

	if len(parsedURL.User.Username()) < 1 {
		parsedURL.User = url.User("root")
	}
	if len(parsedURL.Path) < 1 {
		parsedURL.Path = "/nakama"
	}

	// Resolve initial database address based on host before connecting.
	dbHostname := parsedURL.Hostname()
	resolvedAddr, resolvedAddrMap := dbResolveAddress(ctx, logger, dbHostname)

	logger.Debug("Complete database connection URL", zap.String("raw_url", parsedURL.String()))
	db, err := sql.Open("pgx", parsedURL.String())
	if err != nil {
		logger.Fatal("Error connecting to database", zap.Error(err))
	}
	// Limit max time allowed across database ping and version fetch to 15 seconds total.
	pingCtx, pingCtxCancelFn := context.WithTimeout(ctx, 15*time.Second)
	defer pingCtxCancelFn()
	if err = db.PingContext(pingCtx); err != nil {
		if strings.HasSuffix(err.Error(), "does not exist (SQLSTATE 3D000)") {
			logger.Fatal("Database schema not found, run `nakama migrate up`", zap.Error(err))
		}
		logger.Fatal("Error pinging database", zap.Error(err))
	}

	db.SetConnMaxLifetime(time.Millisecond * time.Duration(config.ConnMaxLifetimeMs))
	db.SetMaxOpenConns(config.MaxOpenConns)
	db.SetMaxIdleConns(config.MaxIdleConns)

	var dbVersion string
	if err = db.QueryRowContext(pingCtx, "SELECT version()").Scan(&dbVersion); err != nil {
		logger.Fatal("Error querying database version", zap.Error(err))
	}

	// Periodically check database hostname for underlying address changes.
	go func() {
		ticker := time.NewTicker(time.Duration(config.DnsScanIntervalSec) * time.Second)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				newResolvedAddr, newResolvedAddrMap := dbResolveAddress(ctx, logger, dbHostname)
				if len(resolvedAddr) == 0 {
					// Could only happen when initial resolve above failed, and all resolves since have also failed.
					// Trust the database driver in this case.
					resolvedAddr = newResolvedAddr
					resolvedAddrMap = newResolvedAddrMap
					break
				}
				if len(newResolvedAddr) == 0 {
					// New addresses failed to resolve, but had previous ones. Trust the database driver in this case.
					break
				}

				// Check for any changes in the resolved addresses.
				drain := len(resolvedAddrMap) != len(newResolvedAddrMap)
				if !drain {
					for addr := range newResolvedAddrMap {
						if _, found := resolvedAddrMap[addr]; !found {
							drain = true
							break
						}
					}
				}
				if !drain {
					// No changes.
					break
				}

				startTime := time.Now().UTC()
				logger.Warn("Database starting rotation of all connections due to address change",
					zap.Int("count", config.MaxOpenConns),
					zap.Strings("previous", resolvedAddr),
					zap.Strings("updated", newResolvedAddr))

				// Changes found. Drain the pool and allow the database driver to open fresh connections.
				// Rely on the database driver to re-do its own hostname to address resolution.
				var acquired int
				conns := make([]*sql.Conn, 0, config.MaxOpenConns)
				for acquired < config.MaxOpenConns {
					acquired++
					conn, err := db.Conn(ctx)
					if err != nil {
						if err == context.Canceled {
							// Server shutting down.
							return
						}
						// Log errors acquiring connections, but proceed without the failed connection anyway.
						logger.Error("Error acquiring database connection", zap.Error(err))
						continue
					}
					conns = append(conns, conn)
				}

				resolvedAddr = newResolvedAddr
				resolvedAddrMap = newResolvedAddrMap
				for _, conn := range conns {
					if err := conn.Raw(func(driverConn interface{}) error {
						pgc, ok := driverConn.(*stdlib.Conn)
						if !ok {
							return ErrDatabaseDriverMismatch
						}
						if err := pgc.Close(); err != nil {
							return err
						}
						return nil
					}); err != nil {
						logger.Error("Error closing database connection", zap.Error(err))
					}
					if err := conn.Close(); err != nil {
						logger.Error("Error releasing database connection", zap.Error(err))
					}
				}

				logger.Warn("Database finished rotation of all connections due to address change",
					zap.Int("count", len(conns)),
					zap.Strings("previous", resolvedAddr),
					zap.Strings("updated", newResolvedAddr),
					zap.Duration("elapsed_duration", time.Now().UTC().Sub(startTime)))
			}
		}
	}()

	return db, dbVersion
}

func dbResolveAddress(ctx context.Context, logger *zap.Logger, host string) ([]string, map[string]struct{}) {
	resolveCtx, resolveCtxCancelFn := context.WithTimeout(ctx, 15*time.Second)
	defer resolveCtxCancelFn()
	addr, err := net.DefaultResolver.LookupHost(resolveCtx, host)
	if err != nil {
		logger.Debug("Error resolving database address, using previously resolved address", zap.String("host", host), zap.Error(err))
		return nil, nil
	}
	addrMap := make(map[string]struct{}, len(addr))
	for _, a := range addr {
		addrMap[a] = struct{}{}
	}
	return addr, addrMap
}

// Tx is used to permit clients to implement custom transaction logic.
type Tx interface {
	ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
	Commit() error
	Rollback() error
}

// Scannable Interface to help utility functions accept either *sql.Row or *sql.Rows for scanning one row at a time.
type Scannable interface {
	Scan(dest ...interface{}) error
}

// ExecuteRetryable Retry functions that perform non-transactional database operations.
func ExecuteRetryable(fn func() error) error {
	if err := fn(); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.SerializationFailure {
			// A recognised error type that can be retried.
			return ExecuteRetryable(fn)
		}
		return err
	}
	return nil
}

// ExecuteInTx runs fn inside tx which should already have begun.
// *WARNING*: Do not execute any statements on the supplied tx before calling this function.
// ExecuteInTx will only retry statements that are performed within the supplied
// closure (fn). Any statements performed on the tx before ExecuteInTx is invoked will *not*
// be re-run if the transaction needs to be retried.
//
// fn is subject to the same restrictions as the fn passed to ExecuteTx.
func ExecuteInTx(ctx context.Context, tx Tx, fn func() error) (err error) {
	defer func() {
		if err == nil {
			// Ignore commit errors. The tx has already been committed by RELEASE.
			_ = tx.Commit()
		} else {
			// We always need to execute a Rollback() so sql.DB releases the
			// connection.
			_ = tx.Rollback()
		}
	}()
	// Specify that we intend to retry this txn in case of database retryable errors.
	if _, err = tx.ExecContext(ctx, "SAVEPOINT cockroach_restart"); err != nil {
		return err
	}

	for {
		released := false
		err = fn()
		if err == nil {
			// RELEASE acts like COMMIT in CockroachDB. We use it since it gives us an
			// opportunity to react to retryable errors, whereas tx.Commit() doesn't.
			released = true
			if _, err = tx.ExecContext(ctx, "RELEASE SAVEPOINT cockroach_restart"); err == nil {
				return nil
			}
		}
		// We got an error; let's see if it's a retryable one and, if so, restart. We look
		// for either the standard PG errcode SerializationFailureError:40001 or the Cockroach extension
		// errcode RetriableError:CR000. The Cockroach extension has been removed server-side, but support
		// for it has been left here for now to maintain backwards compatibility.
		var pgErr *pgconn.PgError
		if retryable := errors.As(errorCause(err), &pgErr) && (pgErr.Code == "CR000" || pgErr.Code == pgerrcode.SerializationFailure); !retryable {
			if released {
				err = newAmbiguousCommitError(err)
			}
			return err
		}
		if _, retryErr := tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT cockroach_restart"); retryErr != nil {
			return newTxnRestartError(retryErr, err)
		}
	}
}
