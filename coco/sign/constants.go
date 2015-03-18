package sign

import "time"

// Constants we expect might be used by other packages
// TODO: can this be replaced by the application using the signer?
var ROUND_TIME time.Duration = 10 * time.Second
var HEARTBEAT = ROUND_TIME + ROUND_TIME/2

var RoundsPerView int64 = 3

var FALSE int64 = 0
var TRUE int64 = 1
