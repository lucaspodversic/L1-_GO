package node

// Punto de documentación del paquete node y helper RunMain.
//
// Desviación del plan (Día 15 `node/main.go`): Go no permite varios `main`
// en el mismo directorio. Este fichero pertenece al package `node` y expone
// RunMain; el binario real está en `cmd/l1/main.go`, que llama a node.Main.

import "os"

// RunMain ejecuta la CLI con os.Args[1:] y termina el proceso.
func RunMain() {
	os.Exit(Main(os.Args[1:]))
}
