package p2p

// Bootnodes: lista estática de peers iniciales para unirse a la red.

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Bootnode es una entrada "peerID@host:port" o sólo "host:port".
type Bootnode struct {
	ID   PeerID
	Addr string
}

// ParseBootnode interpreta una línea.
func ParseBootnode(line string) (Bootnode, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return Bootnode{}, fmt.Errorf("p2p: línea vacía")
	}
	if i := strings.IndexByte(line, '@'); i >= 0 {
		id, err := PeerIDFromHex(line[:i])
		if err != nil {
			return Bootnode{}, err
		}
		return Bootnode{ID: id, Addr: line[i+1:]}, nil
	}
	return Bootnode{Addr: line}, nil
}

// LoadBootnodes lee un fichero con un bootnode por línea.
func LoadBootnodes(path string) ([]Bootnode, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Bootnode
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		b, err := ParseBootnode(sc.Text())
		if err != nil {
			continue
		}
		out = append(out, b)
	}
	return out, sc.Err()
}

// ParseBootnodeList interpreta una lista separada por comas.
func ParseBootnodeList(s string) ([]Bootnode, error) {
	var out []Bootnode
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		b, err := ParseBootnode(part)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}
