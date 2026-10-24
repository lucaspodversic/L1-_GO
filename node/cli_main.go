package node

// CLI principal: despacha subcomandos init/run/keys/export.

import (
	"fmt"
	"os"
)

// Main es el punto de entrada del binario (package node). Devuelve código de salida.
// Desviación del plan: en lugar de varios main en el mismo directorio (ilegal en Go),
// node.Main concentra la CLI y cmd/l1/main.go es un entrypoint mínimo.
func Main(args []string) int {
	if len(args) == 0 {
		printUsage()
		return 2
	}
	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "init":
		err = cmdInit(rest)
	case "run":
		err = cmdRun(rest)
	case "keys":
		err = cmdKeys(rest)
	case "export":
		err = cmdExport(rest)
	case "help", "-h", "--help":
		printUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "comando desconocido: %s\n", cmd)
		printUsage()
		return 2
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `l1 — nodo de la cadena L1

Uso:
  l1 init   [flags]   inicializa datadir + génesis + claves
  l1 run    [flags]   arranca el nodo
  l1 keys   [flags]   genera/inspecciona claves
  l1 export [flags]   exporta génesis o estado

`)
}
