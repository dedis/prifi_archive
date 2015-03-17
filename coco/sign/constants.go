package sign

import "time"

// Constants we expect might be used by other packages
// TODO: can this be replaced by the application using the signer?
var ROUND_TIME time.Duration = 2 * time.Second

var RoundsPerView int64 = 3

var FALSE int64 = 0
var TRUE int64 = 1
