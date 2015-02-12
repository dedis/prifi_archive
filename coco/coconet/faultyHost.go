package coconet

type HostState int

const (
	ALIVE HostState = iota
	DEAD
)

const DefaultState HostState = ALIVE

type FaultyHost struct {
	Host

	State HostState
}

func NewFaultyHost(host Host, state ...HostState) FaultyHost {
	var fh FaultyHost

	fh.Host = host
	if len(state) > 0 {
		fh.State = state[0]
	} else {
		fh.State = DefaultState
	}

	return fh
}

func (fh *FaultyHost) Die() {
	fh.State = DEAD
}
