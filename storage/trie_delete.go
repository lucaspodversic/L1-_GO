package storage

// Borrado en el Merkle Patricia Trie. La parte delicada es mantener la
// forma canónica: tras borrar, una rama con un solo hijo debe colapsarse en
// un shortNode, y dos shortNode consecutivos deben fusionarse. Si no, el
// mismo conjunto de claves podría producir raíces distintas según el orden
// de las operaciones, rompiendo el consenso.

// Delete elimina key del trie (no es error si no existe).
func (t *Trie) Delete(key []byte) error { return t.Update(key, nil) }

// delete elimina key del subárbol n. Devuelve si hubo cambios y el nuevo
// subárbol (nil si quedó vacío).
func (t *Trie) delete(n node, prefix, key []byte) (bool, node, error) {
	switch n := n.(type) {
	case *shortNode:
		matchlen := prefixLen(key, n.Key)
		if matchlen < len(n.Key) {
			return false, n, nil // la clave no está en este subárbol
		}
		if matchlen == len(key) {
			return true, nil, nil // coincidencia exacta: se elimina la hoja
		}
		// La clave sigue por debajo: se borra en el hijo.
		dirty, child, err := t.delete(n.Val, concat(prefix, key[:len(n.Key)]), key[len(n.Key):])
		if !dirty || err != nil {
			return false, n, err
		}
		switch child := child.(type) {
		case *shortNode:
			// El hijo se redujo a un shortNode: se fusionan las claves para
			// no dejar dos extensiones seguidas.
			return true, &shortNode{Key: concat(n.Key, child.Key), Val: child.Val, flags: t.newFlag()}, nil
		default:
			return true, &shortNode{Key: n.Key, Val: child, flags: t.newFlag()}, nil
		}

	case *fullNode:
		dirty, nn, err := t.delete(n.Children[key[0]], concat(prefix, key[:1]), key[1:])
		if !dirty || err != nil {
			return false, n, err
		}
		n = n.copy()
		n.flags = t.newFlag()
		n.Children[key[0]] = nn
		if nn != nil {
			return true, n, nil // la rama sigue teniendo ≥2 hijos
		}
		// Se cuenta cuántos hijos quedan: pos ≥ 0 si exactamente uno.
		pos := -1
		for i, c := range &n.Children {
			if c != nil {
				if pos == -1 {
					pos = i
				} else {
					pos = -2
					break
				}
			}
		}
		if pos >= 0 {
			if pos != 16 {
				// El único hijo es un subárbol: si es un shortNode se
				// fusiona con él anteponiendo el nibble de la rama.
				cnode, err := t.resolve(n.Children[pos], concat(prefix, []byte{byte(pos)}))
				if err != nil {
					return false, nil, err
				}
				if cnode, ok := cnode.(*shortNode); ok {
					k := concat([]byte{byte(pos)}, cnode.Key)
					return true, &shortNode{Key: k, Val: cnode.Val, flags: t.newFlag()}, nil
				}
			}
			// Hijo rama o valor: la rama se sustituye por un shortNode de un
			// nibble (o una hoja con sólo el terminador si pos == 16).
			return true, &shortNode{Key: []byte{byte(pos)}, Val: n.Children[pos], flags: t.newFlag()}, nil
		}
		return true, n, nil

	case valueNode:
		return true, nil, nil

	case nil:
		return false, nil, nil

	case hashNode:
		rn, err := t.resolveHash(n, prefix)
		if err != nil {
			return false, nil, err
		}
		dirty, nn, err := t.delete(rn, prefix, key)
		if !dirty || err != nil {
			return false, rn, err
		}
		return true, nn, nil
	}
	panic("trie: tipo de nodo inválido")
}
