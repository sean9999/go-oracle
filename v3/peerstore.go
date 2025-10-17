package oracle

import (
	"encoding/json"
	"oracle2/delphi"
)

type PeerStore map[delphi.PublicKey]Props

func (ps PeerStore) MarshalJSON() ([]byte, error) {
	m := make(map[string]Props)
	for k, v := range ps {
		m[k.String()] = v
	}
	return json.Marshal(m)
}

func (psPtr *PeerStore) UnmarshalJSON(b []byte) error {
	ps := *psPtr
	var m map[string]Props
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	for k, v := range m {
		pub, err := delphi.KeyFromString(k)
		if err != nil {
			return err
		}
		ps[delphi.PublicKey(pub)] = v
	}
	return nil
}
