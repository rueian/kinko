package status

import "errors"

var (
	ErrNoParams = errors.New("should not be empty")
	ErrNoPlugin = errors.New("sealingPlugin not supported")
	ErrBadData  = errors.New("bad data")
	ErrMigrate  = errors.New("fail to migrate")
)

var (
	ReasonSyncSuccess     ConditionReason = "SyncSucceeded"
	ReasonNoPlugin        ConditionReason = "PluginNotSupported"
	ReasonBadData         ConditionReason = "DataBroken"
	ReasonMigrationFailed ConditionReason = "MigrationFailed"
	ReasonNoParams        ConditionReason = "ParamsMissing"
	ReasonUnknown         ConditionReason = "Unknown"
)
