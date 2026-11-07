package api

import "errors"

var (
	ErrBlocked        = errors.New("request blocked by policy")
	ErrHostNotAllowed = errors.New("host not in allowlist")
	ErrSecretLeak     = errors.New("secret placeholder sent to unauthorized host")
	// ErrRequestDenied: a request on an allowed host that a deny_requests rule
	// names (patch 10) -- refused before any secret is put in.
	ErrRequestDenied = errors.New("request denied by policy")
	// ErrHostMismatch: inside a TLS connection whose server name the allowlist
	// admitted, a request named another host (patch 10) -- a CDN that serves
	// many sites on one address would route it to a site that was never allowed.
	ErrHostMismatch  = errors.New("Host header does not match the TLS server name")
	ErrVMNotRunning  = errors.New("VM is not running")
	ErrVMNotFound    = errors.New("VM not found")
	ErrTimeout       = errors.New("operation timed out")
	ErrInvalidConfig = errors.New("invalid configuration")

	ErrInvalidVolumeFormat = errors.New("expected format host:guest or host:guest:option[,option...]")
	ErrResolvePath         = errors.New("failed to resolve path")
	ErrHostPathNotExist    = errors.New("host path does not exist")
	ErrUnknownMountOption  = errors.New("unknown option")
	ErrInvalidMountOwner   = errors.New("invalid mount owner")
	ErrGuestPathNotAbs     = errors.New("guest path must be absolute")
	ErrGuestPathOutside    = errors.New("guest path must be within workspace")

	ErrEnvNameEmpty   = errors.New("environment variable name cannot be empty")
	ErrEnvNameInvalid = errors.New("environment variable name is invalid")
	ErrEnvVarNotSet   = errors.New("environment variable is not set")
	ErrReadEnvFile    = errors.New("read env file")
	ErrEnvFileLine    = errors.New("parse env file line")

	ErrPortForwardSpecFormat = errors.New("invalid port-forward spec format")
	ErrPortForwardPort       = errors.New("invalid port")

	ErrAddHostSpecFormat = errors.New("invalid add-host format")
	ErrAddHostHost       = errors.New("invalid add-host hostname")
	ErrAddHostIP         = errors.New("invalid add-host ip")
)
