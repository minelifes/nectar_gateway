package store

// driverName is the database/sql driver registered by this package (tests open raw databases).
func driverName() string { return "sqlite" }
